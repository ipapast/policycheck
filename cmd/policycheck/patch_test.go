package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func patchHook(t *testing.T, cwd, patch string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"tool_name": "apply_patch", "cwd": cwd,
		"tool_input": map[string]string{"command": patch},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPatchOperations(t *testing.T) {
	bin := buildBinary(t)
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"ordinary add", "*** Add File: src/example.txt\n+hello", 0},
		{"ordinary update", "*** Update File: src/example.txt\n@@\n-old\n+new", 0},
		{"implicit first hunk", "*** Update File: src/example.txt\n-old\n+new", 0},
		{"ordinary delete", "*** Delete File: src/example.txt", 0},
		{"ordinary move", "*** Update File: src/example.txt\n*** Move to: src/renamed.txt\n@@\n-old\n+new", 0},
		{"workflow update", "*** Update File: .github/workflows/ci.yml\n@@\n-old\n+new", 2},
		{"workflow delete", "*** Delete File: .github/workflows/ci.yml", 2},
		{"move into workflow", "*** Update File: safe.txt\n*** Move to: .github/workflows/ci.yml\n@@\n-old\n+new", 2},
		{"move out of workflow", "*** Update File: .github/workflows/ci.yml\n*** Move to: safe.txt\n@@\n-old\n+new", 2},
		{"safe then protected", "*** Add File: safe.txt\n+hello\n*** Add File: .github/workflows/ci.yml\n+name: test", 2},
		{"relative traversal", "*** Add File: src/../.github/workflows/ci.yml\n+name: test", 2},
		{"absolute path", "*** Add File: /tmp/example/.github/workflows/ci.yml\n+name: test", 2},
		{"path with spaces", "*** Add File: my repo/.github/workflows/ci.yml\n+name: test", 2},
		{"shell config", "*** Update File: .zshrc\n@@\n-old\n+new", 2},
		{"Claude settings", "*** Add File: .claude/settings.json\n+{}", 2},
		{"Codex hooks", "*** Add File: .codex/hooks.json\n+{}", 2},
		{"Codex config", "*** Update File: .codex/config.toml\n@@\n-old\n+new", 2},
		{"Codex requirements", "*** Delete File: .codex/requirements.toml", 2},
		{"Codex hook script", "*** Update File: .codex/hooks/check.py\n@@\n-old\n+new", 2},
		{"Codex rules", "*** Delete File: .codex/rules/default.rules", 2},
		{"header text is just content", "*** Add File: docs/example.txt\n+*** Delete File: .github/workflows/ci.yml\n+*** End Patch", 0},
		{"header text is update context", "*** Update File: docs/example.txt\n@@\n *** Delete File: .github/workflows/ci.yml\n+example", 0},
		{"whitespace around add header", "  *** Add File: .github/workflows/ci.yml  \n+name: test", 2},
		{"CRLF patch", "*** Add File: .github/workflows/ci.yml\r\n+name: test\r", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := patchHook(t, dir, "*** Begin Patch\n"+tc.body+"\n*** End Patch")
			if got := runWithEnv(t, bin, dir, input); got != tc.want {
				t.Fatalf("exit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPatchResolvesHookCwdAndSymlinkTargets(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(filepath.Join(workflows, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(workflows, filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(workflows, "nested"), filepath.Join(dir, "deep")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"alias/ci.yml", "alias/new/ci.yml", "deep/../ci.yml"} {
		patch := "*** Begin Patch\n*** Add File: " + path + "\n+name: test\n*** End Patch"
		// The hook payload's cwd, not the hook process directory, resolves relative paths.
		if got := runWithEnv(t, bin, t.TempDir(), patchHook(t, dir, patch)); got != 2 {
			t.Errorf("path %q: exit = %d, want 2", path, got)
		}
	}
}

func TestPatchAppliesCustomWriteAndEditPolicies(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	policy := `permit(principal, action, resource);
@id("CUSTOM-WRITE") forbid(principal, action == Action::"Write", resource) when { context.file_path like "*/write.txt" };
@id("CUSTOM-EDIT") forbid(principal, action == Action::"Edit", resource) when { context.file_path like "*/edit.txt" };`
	if err := os.WriteFile(filepath.Join(dir, "custom.cedar"), []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		"*** Add File: edit.txt\n+new",
		"*** Update File: write.txt\n@@\n-old\n+new",
		"*** Delete File: edit.txt",
		"*** Update File: safe.txt\n*** Move to: write.txt\n@@\n-old\n+new",
	} {
		if got := runEvaluate(t, bin, dir, patchHook(t, "", "*** Begin Patch\n"+body+"\n*** End Patch")); got != 2 {
			t.Errorf("custom policy not enforced: %q exit = %d", body, got)
		}
	}
}

func TestPatchMalformedInputFailsClosed(t *testing.T) {
	bin := buildBinary(t)
	for _, patch := range []string{
		"", "garbage", "*** Begin Patch\n*** Add File: safe.txt\n+hello",
		"*** Begin Patch\n*** Add File: \n+hello\n*** End Patch",
		"*** Begin Patch\n*** Copy File: safe.txt\n*** End Patch",
		"*** Begin Patch\n*** Move to: safe.txt\n*** End Patch",
		"*** Begin Patch\n*** Add File: safe.txt\nhello\n*** End Patch",
		"*** Begin Patch\n*** Add File: safe.txt\n+hello\n*** End Patch\n*** Delete File: .github/workflows/ci.yml",
	} {
		dir := t.TempDir()
		if got := runWithEnv(t, bin, dir, patchHook(t, dir, patch)); got != 2 {
			t.Errorf("malformed patch %q: exit = %d, want 2", patch, got)
		}
	}
}

func TestPatchScopedIgnoresAndAudit(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	ignoredPath := filepath.Join(resolvedDir, "allowed", ".github", "workflows", "ci.yml")
	blockedPath := filepath.Join(resolvedDir, "blocked", ".github", "workflows", "ci.yml")
	ignores, _ := json.Marshal([]ignoreEntry{{Policy: "TOOL-005", Path: filepath.Join(dir, "allowed"), Expires: "2999-01-01"}})
	if err := os.WriteFile(filepath.Join(dir, ".cedar-ignores.json"), ignores, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	env := "POLICYCHECK_AUDIT_LOG=" + logPath
	patch := "*** Begin Patch\n*** Add File: allowed/.github/workflows/ci.yml\n+name: test\n*** End Patch"
	if got := runWithEnv(t, bin, dir, patchHook(t, dir, patch), env); got != 0 {
		t.Fatalf("ignored patch exit = %d", got)
	}
	patch = strings.Replace(patch, "*** End Patch", "*** Add File: blocked/.github/workflows/ci.yml\n+name: test\n*** End Patch", 1)
	if got := runWithEnv(t, bin, dir, patchHook(t, dir, patch), env); got != 2 {
		t.Fatalf("mixed patch exit = %d, want 2", got)
	}
	entries := readAudit(t, logPath)
	if len(entries) != 2 || entries[0]["decision"] != "allow" || entries[1]["decision"] != "block" || entries[1]["tool"] != "apply_patch" {
		t.Fatalf("unexpected audit entries: %v", entries)
	}
	vs := entries[1]["violations"].([]any)
	if len(vs) != 2 {
		t.Fatalf("want both paths logged, got %v", vs)
	}
	if v := vs[0].(map[string]any); v["file_path"] != ignoredPath || v["ignored"] != true {
		t.Errorf("ignored path: %v", v)
	}
	if v := vs[1].(map[string]any); v["file_path"] != blockedPath || v["ignored"] == true {
		t.Errorf("blocked path: %v", v)
	}
	// Neither an unrelated file nor a path quoted in the body may widen an ignore.
	patch = "*** Begin Patch\n*** Add File: blocked/.github/workflows/ci.yml\n+" + ignoredPath + "\n*** End Patch"
	if got := runWithEnv(t, bin, dir, patchHook(t, dir, patch)); got != 2 {
		t.Fatalf("path in content bypassed ignore: exit = %d", got)
	}
	// A link inside the ignored directory must not widen its scope to a
	// protected target elsewhere.
	if err := os.MkdirAll(filepath.Join(dir, "allowed"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blocked"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "blocked"), filepath.Join(dir, "allowed", "link")); err != nil {
		t.Fatal(err)
	}
	patch = "*** Begin Patch\n*** Add File: allowed/link/.github/workflows/ci.yml\n+name: test\n*** End Patch"
	if got := runWithEnv(t, bin, dir, patchHook(t, dir, patch)); got != 2 {
		t.Fatalf("symlink escaped scoped ignore: exit = %d", got)
	}
}

func TestPatchBlocksWorkflowCreation(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := patchHook(t, dir, "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: test\n*** End Patch")
	if got := runWithEnv(t, bin, dir, input); got != 2 {
		t.Fatalf("workflow creation exit = %d, want 2", got)
	}
}
