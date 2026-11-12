package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, bin, dir, input string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(output)
	}
	t.Fatalf("run CLI: %v", err)
	return -1, string(output)
}

// Exercise decoding, policy loading, evaluation and the actual blocking exit
// code for every fixture, with both the standalone binary and policies on disk.
func TestPolicyFixturesThroughCLI(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	policies, err := filepath.Abs("../../policies")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(policies, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, "_test.json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var cases []testCase
		if err := json.Unmarshal(data, &cases); err != nil {
			return err
		}
		for _, tc := range cases {
			for _, mode := range []string{"embedded", "disk"} {
				t.Run(filepath.Base(path)+"/"+tc.Name+"/"+mode, func(t *testing.T) {
					input, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tc.ToolName, "tool_input": tc.ToolInput, "cwd": dir})
					if err != nil {
						t.Fatal(err)
					}
					var args []string
					if mode == "disk" {
						args = []string{policies}
					}
					want := 0
					if tc.Expect == "block" {
						want = 2
					}
					if got, output := runCLI(t, bin, dir, string(input), args...); got != want {
						t.Fatalf("exit = %d, want %d: %s", got, want, output)
					}
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIgnoreLifecycleThroughCLI(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	check := func(want int, input string, args ...string) string {
		t.Helper()
		got, output := runCLI(t, bin, dir, input, args...)
		if got != want {
			t.Fatalf("%v: exit = %d, want %d: %s", args, got, want, output)
		}
		return output
	}
	blocked := `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/cedar-lifecycle"}}`
	check(2, blocked)
	check(0, "", "ignore", "CMD-001", "--reason", "test", "--path", "/tmp/cedar-lifecycle", "--expires", "2999-01-01")
	if output := check(0, "", "list-ignores"); !strings.Contains(output, "CMD-001") || !strings.Contains(output, "test") {
		t.Fatalf("missing ignore: %s", output)
	}
	if output := check(0, blocked); !strings.Contains(output, "IGNORED [CMD-001]") {
		t.Fatalf("missing ignore feedback: %s", output)
	}
	check(2, `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/cedar-lifecycle-other"}}`)
	check(0, "", "ignore", "CMD-001", "--path", "/tmp/cedar-lifecycle", "--expires", "2000-01-01")
	check(2, blocked)
	if output := check(0, "", "list-ignores"); !strings.Contains(output, "No active ignores") {
		t.Fatalf("expired ignore listed: %s", output)
	}
	check(0, "", "unignore", "CMD-001")
	check(2, blocked)
	check(1, "", "unignore", "CMD-001")
	check(1, "", "ignore")
	check(1, "", "unignore")
	check(1, "", "ignore", "CMD-001", "--expires", "invalid")
	if err := os.WriteFile(filepath.Join(dir, ".cedar-ignores.json"), []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	check(2, blocked)
	check(1, "", "list-ignores")
}

func TestFilePolicyFixturesThroughPatchCLI(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	err := filepath.WalkDir("../../policies", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, "_test.json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var cases []testCase
		if err := json.Unmarshal(data, &cases); err != nil {
			return err
		}
		for _, tc := range cases {
			if tc.ToolName != "Write" && tc.ToolName != "Edit" {
				continue
			}
			file := tc.ToolInput["file_path"].(string)
			operations := map[string]string{
				"add":      "*** Add File: " + file + "\n+new",
				"update":   "*** Update File: " + file + "\n@@\n-old\n+new",
				"delete":   "*** Delete File: " + file,
				"move in":  "*** Update File: safe-source.txt\n*** Move to: " + file + "\n@@\n-old\n+new",
				"move out": "*** Update File: " + file + "\n*** Move to: safe-destination.txt\n@@\n-old\n+new",
			}
			for operation, body := range operations {
				t.Run(tc.Name+"/"+operation, func(t *testing.T) {
					want := 0
					if tc.Expect == "block" {
						want = 2
					}
					input := patchHook(t, dir, "*** Begin Patch\n"+body+"\n*** End Patch")
					if got, output := runCLI(t, bin, dir, input); got != want {
						t.Fatalf("exit = %d, want %d: %s", got, want, output)
					}
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAuditWritesThroughCLI(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	const calls = 32
	// The nested Run waits for all its parallel subtests before checking the log.
	t.Run("writers", func(t *testing.T) {
		for i := 0; i < calls; i++ {
			t.Run("block", func(t *testing.T) {
				t.Parallel()
				input := `{"tool_name":"Bash","tool_input":{"command":"git push --force origin test"}}`
				if got := runWithEnv(t, bin, dir, input, "POLICYCHECK_AUDIT_LOG="+logPath); got != 2 {
					t.Fatalf("exit = %d, want 2", got)
				}
			})
		}
	})
	entries := readAudit(t, logPath)
	if len(entries) != calls {
		t.Fatalf("audit records = %d, want %d", len(entries), calls)
	}
	for _, entry := range entries {
		if entry["decision"] != "block" || entry["tool"] != "Bash" {
			t.Fatalf("unexpected audit record: %v", entry)
		}
	}
}
