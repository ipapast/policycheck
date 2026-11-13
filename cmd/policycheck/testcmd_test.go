package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runTestCmd(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"test"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	t.Fatal(err)
	return "", -1
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const noRmPolicy = `@id("X-001")
@msg("no rm")
forbid (principal is Agent, action == Action::"Bash", resource)
when { context.command like "rm *" };
`

const permitAll = `permit (principal, action, resource);
`

func newPolicyDir(t *testing.T, fixture string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "base.cedar"), permitAll)
	writeFile(t, filepath.Join(dir, "X-001.cedar"), noRmPolicy)
	if fixture != "" {
		writeFile(t, filepath.Join(dir, "X-001_test.json"), fixture)
	}
	return dir
}

func TestTestCmdPassesOnShippedPolicies(t *testing.T) {
	bin := buildBinary(t)
	policies, _ := filepath.Abs("../../policies")
	for _, args := range [][]string{{policies}, {}} {
		out, code := runTestCmd(t, bin, args...)
		if code != 0 {
			t.Fatalf("args %v: exit %d\n%s", args, code, out)
		}
		if !strings.Contains(out, "passed") || !strings.Contains(out, "0 failed") {
			t.Errorf("args %v: summary missing from output:\n%s", args, out)
		}
	}
}

func TestTestCmdReportsFailingCase(t *testing.T) {
	bin := buildBinary(t)
	dir := newPolicyDir(t, `[
  {"name": "blocks rm", "tool_name": "Bash", "tool_input": {"command": "rm x"}, "expect": "block"},
  {"name": "wrongly expects ls blocked", "tool_name": "Bash", "tool_input": {"command": "ls"}, "expect": "block"}
]`)
	out, code := runTestCmd(t, bin, dir)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "wrongly expects ls blocked") || !strings.Contains(out, "X-001_test.json") {
		t.Errorf("failing case and file not named:\n%s", out)
	}
	if !strings.Contains(out, "1 passed") || !strings.Contains(out, "1 failed") {
		t.Errorf("summary wrong:\n%s", out)
	}
}

func TestTestCmdRejectsBadFixtures(t *testing.T) {
	bin := buildBinary(t)
	cases := map[string]string{
		"unknown expect": `[{"name": "n", "tool_name": "Bash", "tool_input": {"command": "ls"}, "expect": "maybe"}]`,
		"bad json":       `[{`,
	}
	for name, fixture := range cases {
		dir := newPolicyDir(t, fixture)
		if out, code := runTestCmd(t, bin, dir); code != 1 {
			t.Errorf("%s: exit = %d, want 1\n%s", name, code, out)
		}
	}
}

func TestTestCmdFailsWithoutFixtures(t *testing.T) {
	bin := buildBinary(t)
	dir := newPolicyDir(t, "")
	if out, code := runTestCmd(t, bin, dir); code != 1 {
		t.Errorf("exit = %d, want 1 when no *_test.json files exist\n%s", code, out)
	}
}
