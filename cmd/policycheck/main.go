package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
)

type hookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	} `json:"tool_input"`
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
		fmt.Fprintf(os.Stderr, "usage: policycheck <policies-dir>\n")
		fmt.Fprintf(os.Stderr, "       policycheck ignore <policy-id> [--reason <reason>] [--path <pattern>] [--expires <date>]\n")
		fmt.Fprintf(os.Stderr, "       policycheck list-ignores\n")
		fmt.Fprintf(os.Stderr, "       policycheck unignore <policy-id>\n")
		os.Exit(1)
	}

	switch os.Args[1] {
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
func isIgnored(id string, ignores []ignoreEntry, command string, filePath string) *ignoreEntry {
	now := time.Now()
	for i, e := range ignores {
		if e.Policy != id {
			continue
		}
		if e.Expires != "" {
			exp, err := time.Parse("2006-01-02", e.Expires)
			if err == nil && now.After(exp) {
				continue // expired
			}
		}
		// If path is set, only ignore when command or file_path matches
		if e.Path != "" {
			input := command + filePath
			if !containsPattern(input, e.Path) {
				continue
			}
		}
		return &ignores[i]
	}
	return nil
}

func containsPattern(s, pattern string) bool {
	return strings.Contains(s, pattern)
}

func cmdIgnore() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: policycheck ignore <policy-id> [--reason <reason>] [--path <pattern>] [--expires <date>]\n")
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

func cmdEvaluate(policiesDir string) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(1)
	}

	var hook hookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse hook input: %v\n", err)
		os.Exit(1)
	}

	ps, err := loadPolicies(policiesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policies: %v\n", err)
		os.Exit(1)
	}

	ignores, _ := loadIgnores() // ignore errors, just evaluate without ignores

	// Build Cedar request: principal=Agent, action=ToolName, resource=args
	context := cedar.RecordMap{}
	if hook.ToolInput.Command != "" {
		context["command"] = cedar.String(hook.ToolInput.Command)
	}
	if hook.ToolInput.FilePath != "" {
		context["file_path"] = cedar.String(hook.ToolInput.FilePath)
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID("Agent", "claude"),
		Action:    cedar.NewEntityUID("Action", cedar.String(hook.ToolName)),
		Resource:  cedar.NewEntityUID("Resource", "tool_call"),
		Context:   cedar.NewRecord(context),
	}

	decision, diag := ps.IsAuthorized(cedar.EntityMap{}, req)

	if decision == cedar.Deny {
		id := "unknown"
		msg := ""
		if len(diag.Reasons) > 0 {
			id = string(diag.Reasons[0].PolicyID)
		}
		// Look up @msg annotation from the matching policy
		if len(diag.Reasons) > 0 {
			for pid, p := range ps.All() {
				if pid == diag.Reasons[0].PolicyID {
					if ann := p.Annotations(); ann != nil {
						if v, ok := ann["msg"]; ok {
							msg = string(v)
						}
					}
					break
				}
			}
		}

		// Check if this policy is ignored
		if ign := isIgnored(id, ignores, hook.ToolInput.Command, hook.ToolInput.FilePath); ign != nil {
			fmt.Fprintf(os.Stderr, "IGNORED [%s]: %s (reason: %s, expires: %s)\n", id, msg, ign.Reason, ign.Expires)
			return // exit 0, allow
		}

		if msg != "" {
			fmt.Fprintf(os.Stderr, "BLOCKED [%s]: %s\n", id, msg)
		} else {
			fmt.Fprintf(os.Stderr, "BLOCKED [%s]\n", id)
		}
		os.Exit(2)
	}
}

func loadPolicies(dir string) (*cedar.PolicySet, error) {
	ps := cedar.NewPolicySet()
	found := 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".cedar" {
			return nil
		}

		data, err := os.ReadFile(path)
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
		return nil, fmt.Errorf("no .cedar files found in %s", dir)
	}

	return ps, nil
}
