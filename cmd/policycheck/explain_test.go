package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type cliRun struct {
	stdout, stderr string
	code           int
}

func runTool(t *testing.T, bin, dir string, env []string, args ...string) cliRun {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return cliRun{out.String(), errb.String(), code}
}

func TestExplainShowsRuleMessageSourceAndCases(t *testing.T) {
	bin := buildBinary(t)
	res := runTool(t, bin, t.TempDir(), nil, "explain", "CMD-001")
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s%s", res.code, res.stdout, res.stderr)
	}
	for _, want := range []string{
		"CMD-001",
		"rm -r/-rf on dangerous paths",
		"forbid",
		"blocks rm -rf /",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("output missing %q:\n%s", want, res.stdout)
		}
	}
}

func TestExplainIncludesVariants(t *testing.T) {
	bin := buildBinary(t)
	res := runTool(t, bin, t.TempDir(), nil, "explain", "DATA-002")
	if res.code != 0 || !strings.Contains(res.stdout, "DATA-002b") {
		t.Errorf("explain DATA-002 should also show DATA-002b (exit %d):\n%s", res.code, res.stdout)
	}
}

func TestExplainListsAllRules(t *testing.T) {
	bin := buildBinary(t)
	res := runTool(t, bin, t.TempDir(), nil, "explain")
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s", res.code, res.stderr)
	}
	for _, id := range []string{"CMD-001", "NET-004", "TOOL-009"} {
		if !strings.Contains(res.stdout, id) {
			t.Errorf("list is missing %s:\n%s", id, res.stdout)
		}
	}
}

func TestExplainUnknownRule(t *testing.T) {
	bin := buildBinary(t)
	res := runTool(t, bin, t.TempDir(), nil, "explain", "NOPE-999")
	if res.code != 1 || !strings.Contains(res.stderr, "NOPE-999") {
		t.Errorf("exit = %d, stderr = %q; want 1 naming the unknown rule", res.code, res.stderr)
	}
}

func TestExplainCustomDirectoryAndAskDecision(t *testing.T) {
	bin := buildBinary(t)
	dir := askPolicyDir(t)
	writeFile(t, filepath.Join(dir, "ASK-001_test.json"), `[
  {"name": "asks before deleting a repo", "tool_name": "Bash", "tool_input": {"command": "gh repo delete foo"}, "expect": "block"}
]`)
	res := runTool(t, bin, t.TempDir(), nil, "explain", "ASK-001", dir)
	if res.code != 0 {
		t.Fatalf("exit = %d\n%s%s", res.code, res.stdout, res.stderr)
	}
	for _, want := range []string{"ASK-001", "deleting a GitHub repo needs a human", "ask", "asks before deleting a repo"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("output missing %q:\n%s", want, res.stdout)
		}
	}
}
