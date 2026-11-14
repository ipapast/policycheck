package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hookEntry struct {
	Matcher string `json:"matcher"`
	Hooks   []struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	} `json:"hooks"`
}

func readPreToolUse(t *testing.T, path string) (map[string]json.RawMessage, []hookEntry) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("%s is not valid JSON: %v\n%s", path, err, data)
	}
	var hooks map[string][]hookEntry
	if err := json.Unmarshal(top["hooks"], &hooks); err != nil {
		t.Fatalf("bad hooks in %s: %v", path, err)
	}
	return top, hooks["PreToolUse"]
}

func countPolicycheck(entries []hookEntry) int {
	n := 0
	for _, e := range entries {
		for _, h := range e.Hooks {
			if filepath.Base(strings.Fields(h.Command)[0]) == "policycheck" {
				n++
			}
		}
	}
	return n
}

func TestInitClaudeCreatesProjectSettings(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	res := runTool(t, bin, dir, []string{"HOME=" + t.TempDir()}, "init", "claude")
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s%s", res.code, res.stdout, res.stderr)
	}
	_, entries := readPreToolUse(t, filepath.Join(dir, ".claude", "settings.json"))
	if len(entries) != 1 || entries[0].Matcher != "" || len(entries[0].Hooks) != 1 || entries[0].Hooks[0].Type != "command" {
		t.Fatalf("unexpected hook entries: %+v", entries)
	}
	if countPolicycheck(entries) != 1 {
		t.Errorf("hook command should run policycheck: %+v", entries)
	}
}

func TestInitCodexUsesBashAndApplyPatchMatcher(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	res := runTool(t, bin, dir, []string{"HOME=" + t.TempDir()}, "init", "codex")
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s%s", res.code, res.stdout, res.stderr)
	}
	_, entries := readPreToolUse(t, filepath.Join(dir, ".codex", "hooks.json"))
	if len(entries) != 1 || entries[0].Matcher != "^(Bash|apply_patch)$" || countPolicycheck(entries) != 1 {
		t.Errorf("unexpected hook entries: %+v", entries)
	}
	if !strings.Contains(res.stdout, "/hooks") {
		t.Errorf("should remind the user to review and trust the hook in Codex:\n%s", res.stdout)
	}
}

func TestInitIsIdempotent(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	env := []string{"HOME=" + t.TempDir()}
	runTool(t, bin, dir, env, "init", "claude")
	res := runTool(t, bin, dir, env, "init", "claude")
	if res.code != 0 || !strings.Contains(res.stdout, "already") {
		t.Errorf("second run: exit = %d, stdout = %q; want success saying already configured", res.code, res.stdout)
	}
	_, entries := readPreToolUse(t, filepath.Join(dir, ".claude", "settings.json"))
	if countPolicycheck(entries) != 1 {
		t.Errorf("hook was added twice: %+v", entries)
	}
}

func TestInitKeepsExistingSettings(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	writeFile(t, path, `{
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {
    "PreToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "my-other-hook"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "fmt-hook"}]}]
  }
}`)
	res := runTool(t, bin, dir, []string{"HOME=" + t.TempDir()}, "init", "claude")
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s%s", res.code, res.stdout, res.stderr)
	}
	top, entries := readPreToolUse(t, path)
	if len(entries) != 2 || entries[0].Hooks[0].Command != "my-other-hook" || countPolicycheck(entries) != 1 {
		t.Errorf("existing PreToolUse hook should stay first and policycheck be added: %+v", entries)
	}
	if !strings.Contains(string(top["permissions"]), "Bash(ls:*)") {
		t.Errorf("permissions were lost: %s", top["permissions"])
	}
	if !strings.Contains(string(top["hooks"]), "fmt-hook") {
		t.Errorf("PostToolUse hook was lost: %s", top["hooks"])
	}
}

func TestInitUserFlagWritesToHome(t *testing.T) {
	bin := buildBinary(t)
	dir, home := t.TempDir(), t.TempDir()
	res := runTool(t, bin, dir, []string{"HOME=" + home}, "init", "claude", "--user")
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s%s", res.code, res.stdout, res.stderr)
	}
	_, entries := readPreToolUse(t, filepath.Join(home, ".claude", "settings.json"))
	if countPolicycheck(entries) != 1 {
		t.Errorf("hook missing from user settings: %+v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude")); err == nil {
		t.Error("--user must not create project settings")
	}
}

func TestInitDryRunWritesNothing(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	res := runTool(t, bin, dir, []string{"HOME=" + t.TempDir()}, "init", "claude", "--dry-run")
	if res.code != 0 || !strings.Contains(res.stdout, "PreToolUse") {
		t.Errorf("dry run: exit = %d, stdout = %q; want the JSON printed", res.code, res.stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude")); err == nil {
		t.Error("--dry-run must not write files")
	}
}

func TestInitRefusesInvalidJSON(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	writeFile(t, path, `{ "hooks": `)
	res := runTool(t, bin, dir, []string{"HOME=" + t.TempDir()}, "init", "claude")
	if res.code != 1 {
		t.Errorf("exit = %d, want 1", res.code)
	}
	if data, _ := os.ReadFile(path); string(data) != `{ "hooks": ` {
		t.Errorf("invalid settings file was modified: %q", data)
	}
}

func TestInitUnknownAgent(t *testing.T) {
	bin := buildBinary(t)
	res := runTool(t, bin, t.TempDir(), nil, "init", "vim")
	if res.code != 1 || !strings.Contains(res.stderr, "claude") || !strings.Contains(res.stderr, "codex") {
		t.Errorf("exit = %d, stderr = %q; want 1 listing claude and codex", res.code, res.stderr)
	}
}

func TestInitIsIdempotentWhenBinaryHasAnotherName(t *testing.T) {
	bin := buildBinary(t)
	renamed := filepath.Join(t.TempDir(), "pc-renamed")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(renamed, data, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	env := []string{"HOME=" + t.TempDir()}
	runTool(t, renamed, dir, env, "init", "claude")
	res := runTool(t, renamed, dir, env, "init", "claude")
	if !strings.Contains(res.stdout, "already") {
		t.Errorf("second run should say already configured, got %q", res.stdout)
	}
	path := filepath.Join(dir, ".claude", "settings.json")
	data, _ = os.ReadFile(path)
	if strings.Count(string(data), "pc-renamed") != 1 {
		t.Errorf("hook was added twice:\n%s", data)
	}
}

func TestInitWritesMatcherBeforeHooks(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runTool(t, bin, dir, []string{"HOME=" + t.TempDir()}, "init", "claude")
	data, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	s := string(data)
	if strings.Index(s, `"matcher"`) > strings.Index(s, `"hooks": [`) && strings.Count(s, `"hooks"`) > 1 {
		t.Errorf("matcher should come before the hooks list:\n%s", s)
	}
	if strings.Index(s, `"type"`) > strings.Index(s, `"command"`) {
		t.Errorf("type should come before command:\n%s", s)
	}
}
