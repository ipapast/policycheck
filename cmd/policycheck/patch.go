package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/cedar-policy/cedar-go"
)

// patchPaths reads the native Codex patch envelope, not the diff contents.
// Unknown syntax fails closed rather than silently skipping a file operation.
func patchPaths(patch string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(patch), "\r\n", "\n"), "\n")
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "*** Begin Patch" || strings.TrimSpace(lines[len(lines)-1]) != "*** End Patch" {
		return nil, fmt.Errorf("expected Begin Patch / End Patch envelope")
	}
	var paths []string
	operation := ""
	canMove := false
	for _, line := range lines[1 : len(lines)-1] {
		// Codex trims hunk headers, but leading spaces in an Update are
		// diff context and must not be interpreted as another file header.
		header := strings.TrimSpace(line)
		if operation == "Update File" {
			header = strings.TrimRightFunc(line, unicode.IsSpace)
		}
		kind, path := "", ""
		for _, candidate := range []string{"Add File", "Update File", "Delete File", "Move to"} {
			if rest, ok := strings.CutPrefix(header, "*** "+candidate+": "); ok {
				kind, path = candidate, rest
				break
			}
		}
		if kind != "" {
			if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
				return nil, fmt.Errorf("empty or invalid patch path")
			}
			if kind == "Move to" {
				if !canMove {
					return nil, fmt.Errorf("Move to must immediately follow Update File")
				}
				canMove = false
			} else {
				operation = kind
				canMove = kind == "Update File"
			}
			paths = append(paths, path)
			continue
		}
		canMove = false
		switch {
		case operation == "Add File" && strings.HasPrefix(line, "+"):
		case operation == "Update File" && (header == "@@" || strings.HasPrefix(header, "@@ ")):
		case operation == "Update File" && (line == "" || strings.ContainsAny(line[:1], " +-") || header == "*** End of File"):
		default:
			return nil, fmt.Errorf("unsupported patch line %q", line)
		}
	}
	return paths, nil
}

// Check both Write and Edit rules for every mutation, including deletes and
// both ends of a move. This avoids gaps in policies written for only one of
// Claude's file tools. A patch is rejected if any target violates a policy.
func evaluatePatch(ps *cedar.PolicySet, cwd, patch string) ([]violation, error) {
	paths, err := patchPaths(patch)
	if err != nil {
		return nil, err
	}
	if cwd == "" {
		cwd, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	if !filepath.IsAbs(cwd) {
		return nil, fmt.Errorf("patch cwd must be absolute")
	}
	var out []violation
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			// Do not clean before resolving symlinks: link/../file follows
			// the link before walking to the parent on the filesystem.
			path = cwd + string(os.PathSeparator) + path
		}
		resolved, err := resolvePatchPath(path)
		if err != nil {
			return nil, fmt.Errorf("resolve patch path %q: %w", path, err)
		}
		for _, target := range []string{filepath.Clean(path), resolved} {
			for _, action := range []string{"Write", "Edit"} {
				for _, v := range evaluate(ps, action, toolInput{FilePath: filepath.ToSlash(target)}) {
					key := v.ID + "\x00" + resolved
					if !seen[key] {
						seen[key] = true
						v.FilePath = resolved
						out = append(out, v)
					}
				}
			}
		}
	}
	return out, nil
}

// Scopes and violation paths use the same filesystem interpretation. A scope
// that cannot be resolved must not suppress a violation.
func patchIgnores(cwd string, ignores []ignoreEntry) []ignoreEntry {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	var out []ignoreEntry
	for _, entry := range ignores {
		if entry.Path != "" {
			path := entry.Path
			if !filepath.IsAbs(path) {
				path = cwd + string(os.PathSeparator) + path
			}
			resolved, err := resolvePatchPath(path)
			if err != nil {
				continue
			}
			entry.Path = resolved
		}
		out = append(out, entry)
	}
	return out
}

// Resolve existing symlink components while allowing new files/directories.
// Checking both the named and resolved paths protects aliases in either direction.
func resolvePatchPath(path string) (string, error) {
	volume := filepath.VolumeName(path)
	resolved := volume + string(os.PathSeparator)
	for _, part := range strings.Split(path[len(volume):], string(os.PathSeparator)) {
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		resolved = filepath.Join(resolved, part)
		info, err := os.Lstat(resolved)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(resolved)
			if err != nil {
				return "", err
			}
		}
	}
	return resolved, nil
}
