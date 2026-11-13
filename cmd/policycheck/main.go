package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
	cedarpolicies "github.com/ipapast/policycheck"
)

type hookInput struct {
	ToolName  string    `json:"tool_name"`
	ToolInput toolInput `json:"tool_input"`
	Cwd       string    `json:"cwd"`
}

type ignoreEntry struct {
	Policy  string `json:"policy"`
	Reason  string `json:"reason,omitempty"`
	Path    string `json:"path,omitempty"`
	Expires string `json:"expires"`
	Created string `json:"created"`
}

func main() {
	if len(os.Args) < 2 {
		if stdinIsPiped() {
			cmdEvaluate("")
			return
		}
		fmt.Fprintf(os.Stderr, "usage: policycheck [policies-dir]    (reads a hook JSON from stdin; uses the built-in policies when no directory is given)\n")
		fmt.Fprintf(os.Stderr, "       policycheck test [policies-dir]    (run the *_test.json fixtures next to the policies)\n")
		fmt.Fprintf(os.Stderr, "       policycheck ignore <policy-id> [--reason <reason>] [--path <dir>] [--expires <date>]\n")
		fmt.Fprintf(os.Stderr, "       policycheck list-ignores\n")
		fmt.Fprintf(os.Stderr, "       policycheck unignore <policy-id>\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--version", "-version", "version":
		fmt.Printf("policycheck %s\n", versionString())
	case "test":
		cmdTest(os.Args[2:])
	case "ignore":
		cmdIgnore()
	case "list-ignores":
		cmdListIgnores()
	case "unignore":
		cmdUnignore()
	default:
		cmdEvaluate(os.Args[1])
	}
}

func stdinIsPiped() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice == 0
}

func ignoresPath() string {
	return ".cedar-ignores.json"
}

func loadIgnores() ([]ignoreEntry, error) {
	data, err := os.ReadFile(ignoresPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []ignoreEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func saveIgnores(entries []ignoreEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ignoresPath(), append(data, '\n'), 0644)
}

// isIgnored checks if a policy is ignored. If the ignore has a path, it only
// matches when the command or file_path contains that substring.
// policyMatches reports whether an ignore for ignored covers the policy id.
// Ignoring "DATA-002" also covers its variants "DATA-002b", "DATA-002c", etc.
func policyMatches(ignored, id string) bool {
	if ignored == id {
		return true
	}
	suffix, ok := strings.CutPrefix(id, ignored)
	if !ok || suffix == "" {
		return false
	}
	for _, r := range suffix {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func isIgnored(id string, ignores []ignoreEntry, in toolInput) *ignoreEntry {
	now := time.Now()
	for i, e := range ignores {
		if !policyMatches(e.Policy, id) {
			continue
		}
		if e.Expires != "" {
			exp, err := time.Parse("2006-01-02", e.Expires)
			if err == nil && now.After(exp) {
				continue // expired
			}
		}
		if e.Path != "" && !pathScopeMatches(e.Path, in) {
			continue
		}
		return &ignores[i]
	}
	return nil
}

// pathScopeMatches reports whether the call touches scope or something inside
// it. It compares whole path segments, so "/tmp" matches "/tmp/x" but not
// "/tmpfoo" or "/home/me/tmp-secrets".
func pathScopeMatches(scope string, in toolInput) bool {
	scope = strings.TrimRight(scope, "/")
	candidates := []string{in.FilePath, in.Path}
	for _, tok := range strings.Fields(in.Command) {
		tok = strings.Trim(tok, `'"`)
		candidates = append(candidates, tok)
		if _, v, ok := strings.Cut(tok, "="); ok {
			candidates = append(candidates, strings.Trim(v, `'"`))
		}
	}
	for _, c := range candidates {
		if c == scope || strings.HasPrefix(c, scope+"/") {
			return true
		}
	}
	return false
}

func cmdIgnore() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: policycheck ignore <policy-id> [--reason <reason>] [--path <dir>] [--expires <date>]\n")
		os.Exit(1)
	}

	policyID := os.Args[2]
	reason := ""
	path := ""
	expires := time.Now().AddDate(0, 0, 7).Format("2006-01-02") // default: 1 week
	created := time.Now().Format("2006-01-02")

	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--reason":
			if i+1 < len(os.Args) {
				i++
				reason = os.Args[i]
			}
		case "--path":
			if i+1 < len(os.Args) {
				i++
				path = os.Args[i]
			}
		case "--expires":
			if i+1 < len(os.Args) {
				i++
				expires = os.Args[i]
			}
		}
	}

	// Validate expiry date
	if _, err := time.Parse("2006-01-02", expires); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid date format %q, use YYYY-MM-DD\n", expires)
		os.Exit(1)
	}

	ignores, err := loadIgnores()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading ignores: %v\n", err)
		os.Exit(1)
	}

	entry := ignoreEntry{
		Policy:  policyID,
		Reason:  reason,
		Path:    path,
		Expires: expires,
		Created: created,
	}

	// Replace existing ignore for same policy+path combo
	found := false
	for i, e := range ignores {
		if e.Policy == policyID && e.Path == path {
			ignores[i] = entry
			found = true
			break
		}
	}
	if !found {
		ignores = append(ignores, entry)
	}

	if err := saveIgnores(ignores); err != nil {
		fmt.Fprintf(os.Stderr, "error saving ignores: %v\n", err)
		os.Exit(1)
	}

	msg := fmt.Sprintf("Ignored %s until %s", policyID, expires)
	if path != "" {
		msg += fmt.Sprintf(" (path: %s)", path)
	}
	if reason != "" {
		msg += fmt.Sprintf(": %s", reason)
	}
	fmt.Fprintf(os.Stderr, "%s\n", msg)
}

func cmdListIgnores() {
	ignores, err := loadIgnores()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading ignores: %v\n", err)
		os.Exit(1)
	}

	now := time.Now()
	active := 0
	for _, e := range ignores {
		if e.Expires != "" {
			exp, err := time.Parse("2006-01-02", e.Expires)
			if err == nil && now.After(exp) {
				continue
			}
		}
		line := fmt.Sprintf("%s (expires: %s)", e.Policy, e.Expires)
		if e.Path != "" {
			line += fmt.Sprintf(" [path: %s]", e.Path)
		}
		if e.Reason != "" {
			line += fmt.Sprintf(" - %s", e.Reason)
		}
		fmt.Println(line)
		active++
	}
	if active == 0 {
		fmt.Println("No active ignores.")
	}
}

func cmdUnignore() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: policycheck unignore <policy-id>\n")
		os.Exit(1)
	}

	policyID := os.Args[2]

	ignores, err := loadIgnores()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading ignores: %v\n", err)
		os.Exit(1)
	}

	var filtered []ignoreEntry
	removed := false
	for _, e := range ignores {
		if e.Policy == policyID {
			removed = true
			continue
		}
		filtered = append(filtered, e)
	}

	if !removed {
		fmt.Fprintf(os.Stderr, "No ignore found for %s\n", policyID)
		os.Exit(1)
	}

	if err := saveIgnores(filtered); err != nil {
		fmt.Fprintf(os.Stderr, "error saving ignores: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Removed ignore for %s\n", policyID)
}

// Evaluation errors exit 2 (block): Claude Code treats any other non-zero
// exit as a non-blocking error, which would silently disable the guardrails.
func cmdEvaluate(policiesDir string) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(2)
	}

	var hook hookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse hook input: %v\n", err)
		os.Exit(2)
	}

	var ps *cedar.PolicySet
	if policiesDir == "" {
		ps, err = loadEmbeddedPolicies()
	} else {
		ps, err = loadPolicies(policiesDir)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policies: %v\n", err)
		os.Exit(2)
	}

	ignores, _ := loadIgnores() // ignore errors, just evaluate without ignores

	violations := evaluate(ps, hook.ToolName, hook.ToolInput)
	if hook.ToolName == "apply_patch" {
		patchViolations, err := evaluatePatch(ps, hook.Cwd, hook.ToolInput.Command)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to check apply_patch: %v\n", err)
			os.Exit(2)
		}
		violations = append(violations, patchViolations...)
		ignores = patchIgnores(hook.Cwd, ignores)
	}

	var blocked, asked []violation
	for i, v := range violations {
		ignoreInput := hook.ToolInput
		if v.FilePath != "" {
			// A scoped ignore must cover this violation's path, not another
			// file or a string in the patch body.
			ignoreInput = toolInput{FilePath: v.FilePath}
		}
		if ign := isIgnored(v.ID, ignores, ignoreInput); ign != nil {
			violations[i].Ignored = true
			fmt.Fprintf(os.Stderr, "IGNORED [%s]: %s (reason: %s, expires: %s)\n", v.ID, v.Msg, ign.Reason, ign.Expires)
			continue
		}
		if policyAnnotation(ps, v.ID, "decision") == "ask" {
			violations[i].Decision = "ask"
			asked = append(asked, violations[i])
			continue
		}
		blocked = append(blocked, v)
		if v.Msg != "" {
			fmt.Fprintf(os.Stderr, "BLOCKED [%s]: %s\n", v.ID, v.Msg)
		} else {
			fmt.Fprintf(os.Stderr, "BLOCKED [%s]\n", v.ID)
		}
	}

	decision := "allow"
	switch {
	case len(blocked) > 0:
		decision = "block"
	case len(asked) > 0:
		decision = "ask"
	}
	writeAudit(hook.ToolName, hook.ToolInput, violations, decision)
	switch decision {
	case "block":
		os.Exit(2)
	case "ask":
		writeAskDecision(asked)
	}
}

// writeAskDecision tells Claude Code to prompt the user instead of running or
// blocking the call. Rules marked @decision("ask") use this.
func writeAskDecision(asked []violation) {
	reasons := make([]string, 0, len(asked))
	for _, v := range asked {
		if v.Msg != "" {
			reasons = append(reasons, fmt.Sprintf("[%s] %s", v.ID, v.Msg))
		} else {
			reasons = append(reasons, fmt.Sprintf("[%s]", v.ID))
		}
	}
	out := map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "ask",
		"permissionDecisionReason": "policycheck: " + strings.Join(reasons, "; "),
	}}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write hook decision: %v\n", err)
		os.Exit(2)
	}
}

func loadPolicies(dir string) (*cedar.PolicySet, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	return loadPolicyFS(os.DirFS(dir), ".", dir)
}

func loadEmbeddedPolicies() (*cedar.PolicySet, error) {
	return loadPolicyFS(cedarpolicies.FS, "policies", "embedded policies")
}

func loadPolicyFS(fsys fs.FS, root, label string) (*cedar.PolicySet, error) {
	ps := cedar.NewPolicySet()
	found := 0

	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".cedar" {
			return nil
		}

		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var pl cedar.PolicyList
		if err := pl.UnmarshalCedar(data); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		base := filepath.Base(path)
		for i, p := range pl {
			id := fmt.Sprintf("%s#%d", base, i)
			if ann := p.Annotations(); ann != nil {
				if v, ok := ann["id"]; ok {
					id = string(v)
				}
			}
			ps.Add(cedar.PolicyID(id), p)
		}
		found++
		return nil
	})
	if err != nil {
		return nil, err
	}
	if found == 0 {
		return nil, fmt.Errorf("no .cedar files found in %s", label)
	}

	return ps, nil
}
