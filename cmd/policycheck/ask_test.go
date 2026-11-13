package main

import (
	"bytes"
	"encoding/json"
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
	cmd.Env = append(cmd.Environ(), env...)
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
	res := runHook(t, bin, policies, t.TempDir(), "gh repo delete foo")
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
	res := runHook(t, bin, askPolicyDir(t), t.TempDir(), "ls")
	if res.code != 0 || res.stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want 0 and empty", res.code, res.stdout)
	}
}

func TestDenyWinsOverAsk(t *testing.T) {
	bin := buildBinary(t)
	policies := askPolicyDir(t, denyPolicy)
	res := runHook(t, bin, policies, t.TempDir(), "gh repo delete foo")
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
	res := runHook(t, bin, policies, work, "gh repo delete foo")
	if res.code != 0 || res.stdout != "" {
		t.Errorf("exit = %d, stdout = %q; want 0 and empty", res.code, res.stdout)
	}
}

func TestAskDecisionIsAudited(t *testing.T) {
	bin := buildBinary(t)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	runHook(t, bin, askPolicyDir(t), t.TempDir(), "gh repo delete foo", "POLICYCHECK_AUDIT_LOG="+logPath)
	entries := readAudit(t, logPath)
	if len(entries) != 1 || entries[0]["decision"] != "ask" {
		t.Fatalf("want one audit entry with decision ask, got %v", entries)
	}
}
