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

const askPolicy = `@id("ASK-001")
@msg("deleting a GitHub repo needs a human")
@decision("ask")
forbid (principal is Agent, action == Action::"Bash", resource)
when { context.command like "gh repo delete*" };
`

const denyPolicy = `@id("DENY-001")
@msg("gh is not allowed here")
forbid (principal is Agent, action == Action::"Bash", resource)
when { context.command like "gh *" };
`

type hookRun struct {
	stdout, stderr string
	code           int
}

func runHook(t *testing.T, bin, policies, workdir, command string, env ...string) hookRun {
	t.Helper()
	in, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
	cmd := exec.Command(bin, policies)
	cmd.Dir = workdir
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLAUDE") && !strings.HasPrefix(kv, "POLICYCHECK_ASK") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin = bytes.NewReader(in)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return hookRun{out.String(), errb.String(), code}
}

const claudeEnv = "CLAUDE_PROJECT_DIR=/work"

func askPolicyDir(t *testing.T, extra ...string) string {
	dir := newPolicyDir(t, "")
	writeFile(t, filepath.Join(dir, "ASK-001.cedar"), askPolicy)
	for i, p := range extra {
		writeFile(t, filepath.Join(dir, "extra"+string(rune('a'+i))+".cedar"), p)
	}
	return dir
}

func TestAskDecisionPromptsInsteadOfBlocking(t *testing.T) {
	bin := buildBinary(t)
	policies := askPolicyDir(t)
	res := runHook(t, bin, policies, t.TempDir(), "gh repo delete foo", claudeEnv)
	if res.code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", res.code, res.stderr)
	}
	var out struct {
		Hook struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("stdout is not hook JSON: %q (%v)", res.stdout, err)
	}
	if out.Hook.Event != "PreToolUse" || out.Hook.Decision != "ask" {
		t.Errorf("unexpected hook output: %+v", out.Hook)
	}
	if !strings.Contains(out.Hook.Reason, "ASK-001") || !strings.Contains(out.Hook.Reason, "needs a human") {
		t.Errorf("reason should name the rule and message, got %q", out.Hook.Reason)
	}
}

func TestAskDecisionAllowsUnmatchedCallsSilently(t *testing.T) {
	bin := buildBinary(t)
	res := runHook(t, bin, askPolicyDir(t), t.TempDir(), "ls", claudeEnv)
	if res.code != 0 || res.stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want 0 and empty", res.code, res.stdout)
	}
}

func TestDenyWinsOverAsk(t *testing.T) {
	bin := buildBinary(t)
	policies := askPolicyDir(t, denyPolicy)
	res := runHook(t, bin, policies, t.TempDir(), "gh repo delete foo", claudeEnv)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout: %s", res.code, res.stdout)
	}
	if res.stdout != "" {
		t.Errorf("a blocked call should not print a hook decision, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "DENY-001") {
		t.Errorf("stderr should name the blocking rule: %s", res.stderr)
	}
}

func TestIgnoredAskPolicyDoesNotPrompt(t *testing.T) {
	bin := buildBinary(t)
	policies := askPolicyDir(t)
	work := t.TempDir()
	ign := exec.Command(bin, "ignore", "ASK-001", "--reason", "test", "--expires", "2999-01-01")
	ign.Dir = work
	if out, err := ign.CombinedOutput(); err != nil {
		t.Fatalf("ignore: %v\n%s", err, out)
	}
	res := runHook(t, bin, policies, work, "gh repo delete foo", claudeEnv)
	if res.code != 0 || res.stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want 0 and empty", res.code, res.stdout)
	}
}

func TestAskDecisionIsAudited(t *testing.T) {
	bin := buildBinary(t)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	runHook(t, bin, askPolicyDir(t), t.TempDir(), "gh repo delete foo", claudeEnv, "POLICYCHECK_AUDIT_LOG="+logPath)
	entries := readAudit(t, logPath)
	if len(entries) != 1 || entries[0]["decision"] != "ask" {
		t.Fatalf("want one audit entry with decision ask, got %v", entries)
	}
}

func TestAskBlocksOutsideClaudeCode(t *testing.T) {
	bin := buildBinary(t)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	res := runHook(t, bin, askPolicyDir(t), t.TempDir(), "gh repo delete foo", "POLICYCHECK_AUDIT_LOG="+logPath)
	if res.code != 2 || res.stdout != "" {
		t.Fatalf("exit = %d, stdout = %q; want 2 and empty", res.code, res.stdout)
	}
	if !strings.Contains(res.stderr, "ASK-001") || !strings.Contains(res.stderr, "Claude Code") {
		t.Errorf("stderr should name the rule and say ask needs Claude Code: %s", res.stderr)
	}
	if entries := readAudit(t, logPath); len(entries) != 1 || entries[0]["decision"] != "block" {
		t.Errorf("want one audit entry with decision block, got %v", entries)
	}
}

func TestAskOverrideEnvironmentVariable(t *testing.T) {
	bin := buildBinary(t)
	policies := askPolicyDir(t)
	off := runHook(t, bin, policies, t.TempDir(), "gh repo delete foo", claudeEnv, "POLICYCHECK_ASK=off")
	if off.code != 2 {
		t.Errorf("POLICYCHECK_ASK=off under Claude: exit = %d, want 2", off.code)
	}
	on := runHook(t, bin, policies, t.TempDir(), "gh repo delete foo", "POLICYCHECK_ASK=on")
	if on.code != 0 || !strings.Contains(on.stdout, `"permissionDecision":"ask"`) {
		t.Errorf("POLICYCHECK_ASK=on outside Claude: exit = %d, stdout = %q", on.code, on.stdout)
	}
}

func TestInheritedClaudeCodeVariableDoesNotEnableAsk(t *testing.T) {
	bin := buildBinary(t)
	res := runHook(t, bin, askPolicyDir(t), t.TempDir(), "gh repo delete foo", "CLAUDECODE=1")
	if res.code != 2 || res.stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want 2 and empty (CLAUDECODE leaks into agents started from Claude's shell)", res.code, res.stdout)
	}
}

func TestAskExamplePolicyPromptsForPushToMain(t *testing.T) {
	bin := buildBinary(t)
	example, err := os.ReadFile("../../examples/TOOL-009-ask.cedar")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "base.cedar"), permitAll)
	writeFile(t, filepath.Join(dir, "TOOL-009-ask.cedar"), string(example))

	for _, cmd := range []string{"git push origin main", "git push origin master"} {
		res := runHook(t, bin, dir, t.TempDir(), cmd, claudeEnv)
		if res.code != 0 || !strings.Contains(res.stdout, `"permissionDecision":"ask"`) {
			t.Errorf("%q: exit = %d, stdout = %q; want an ask decision", cmd, res.code, res.stdout)
		}
	}
	for _, cmd := range []string{"git push origin feature", "git status"} {
		res := runHook(t, bin, dir, t.TempDir(), cmd, claudeEnv)
		if res.code != 0 || res.stdout != "" {
			t.Errorf("%q: exit = %d, stdout = %q; want a silent allow", cmd, res.code, res.stdout)
		}
	}
}
