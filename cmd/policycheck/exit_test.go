package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "policycheck")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func runEvaluate(t *testing.T, bin, policiesDir, stdin string) int {
	t.Helper()
	cmd := exec.Command(bin, policiesDir)
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader(stdin)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("run failed: %v", err)
	return -1
}

// Claude Code only blocks a tool call on exit code 2, so any evaluation
// error must exit 2 or the guardrails silently turn off.
func TestEvaluateFailsClosed(t *testing.T) {
	bin := buildBinary(t)
	policies, err := filepath.Abs("../../policies")
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"tool_name":"Bash","tool_input":{"command":"ls"}}`

	cases := []struct {
		name, dir, stdin string
		want             int
	}{
		{"malformed JSON", policies, "garbage", 2},
		{"missing policies dir", "/nonexistent-policies-dir", valid, 2},
		{"valid allowed call", policies, valid, 0},
		{"blocked call", policies, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runEvaluate(t, bin, tc.dir, tc.stdin); got != tc.want {
				t.Errorf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}
