package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	bin := buildBinary(t)
	for _, arg := range []string{"--version", "version"} {
		var out bytes.Buffer
		cmd := exec.Command(bin, arg)
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		if !strings.HasPrefix(out.String(), "policycheck ") || len(strings.TrimSpace(out.String())) <= len("policycheck") {
			t.Errorf("%s: unexpected output %q", arg, out.String())
		}
	}
}

func runWithEnv(t *testing.T, bin, dir, stdin string, env ...string) int {
	t.Helper()
	policies, _ := filepath.Abs("../../policies")
	cmd := exec.Command(bin, policies)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatal(err)
	return -1
}

func readAudit(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestAuditLog(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	env := "POLICYCHECK_AUDIT_LOG=" + logPath

	allowed := `{"tool_name":"Bash","tool_input":{"command":"ls"}}`
	blocked := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /opt"}}`

	if code := runWithEnv(t, bin, dir, allowed, env); code != 0 {
		t.Fatalf("allowed call exit = %d", code)
	}
	if entries := readAudit(t, logPath); len(entries) != 0 {
		t.Fatalf("allowed call should not be logged, got %v", entries)
	}

	if code := runWithEnv(t, bin, dir, blocked, env); code != 2 {
		t.Fatalf("blocked call exit = %d", code)
	}
	entries := readAudit(t, logPath)
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e["decision"] != "block" || e["tool"] != "Bash" || e["command"] != "rm -rf /opt" || e["time"] == nil {
		t.Errorf("unexpected entry: %v", e)
	}
	vs, _ := e["violations"].([]any)
	if len(vs) != 1 || vs[0].(map[string]any)["id"] != "CMD-001" {
		t.Errorf("unexpected violations: %v", e["violations"])
	}

	if info, err := os.Stat(logPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("audit log should be mode 0600, got %v (%v)", info, err)
	}
}

func TestAuditLogRecordsIgnoredAndNeverChangesDecision(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	env := "POLICYCHECK_AUDIT_LOG=" + logPath

	ignores := `[{"policy":"CMD-001","expires":"2999-01-01","created":"2026-01-01"}]`
	if err := os.WriteFile(filepath.Join(dir, ".cedar-ignores.json"), []byte(ignores), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /opt"}}`
	if code := runWithEnv(t, bin, dir, blocked, env); code != 0 {
		t.Fatalf("ignored call exit = %d, want 0", code)
	}
	entries := readAudit(t, logPath)
	if len(entries) != 1 || entries[0]["decision"] != "allow" {
		t.Fatalf("want one allow entry for ignored violation, got %v", entries)
	}
	vs := entries[0]["violations"].([]any)
	if vs[0].(map[string]any)["ignored"] != true {
		t.Errorf("violation should be marked ignored: %v", vs)
	}

	badLog := "POLICYCHECK_AUDIT_LOG=" + filepath.Join(dir, "no-such-dir", "audit.jsonl")
	os.Remove(filepath.Join(dir, ".cedar-ignores.json"))
	if code := runWithEnv(t, bin, dir, blocked, badLog); code != 2 {
		t.Errorf("unwritable audit log must not change the decision, exit = %d", code)
	}
}

// The binary must work on its own (e.g. copied into a dev container) with no
// policies directory, no clone and no Go toolchain: defaults are embedded.
func TestEmbeddedPoliciesWorkWithoutDirectory(t *testing.T) {
	bin := buildBinary(t)
	standalone := filepath.Join(t.TempDir(), "policycheck")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(standalone, data, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(stdin string) int {
		cmd := exec.Command(standalone)
		cmd.Dir = t.TempDir()
		cmd.Env = []string{"PATH=/nonexistent"}
		cmd.Stdin = strings.NewReader(stdin)
		err := cmd.Run()
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatal(err)
		return -1
	}

	if got := run(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /opt"}}`); got != 2 {
		t.Errorf("blocked call exit = %d, want 2", got)
	}
	if got := run(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`); got != 0 {
		t.Errorf("allowed call exit = %d, want 0", got)
	}
	if got := run(`garbage`); got != 2 {
		t.Errorf("bad input must still fail closed, exit = %d, want 2", got)
	}
}

func TestEmbeddedPoliciesMatchDisk(t *testing.T) {
	embedded, err := loadEmbeddedPolicies()
	if err != nil {
		t.Fatal(err)
	}
	disk, err := loadPolicies("../../policies")
	if err != nil {
		t.Fatal(err)
	}
	var e, d int
	for range embedded.All() {
		e++
	}
	for range disk.All() {
		d++
	}
	if e != d || e == 0 {
		t.Errorf("embedded has %d policies, disk has %d", e, d)
	}
}
