package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type initTarget struct {
	agent   string
	dir     string
	file    string
	matcher string
}

var initTargets = map[string]initTarget{
	"claude": {agent: "Claude Code", dir: ".claude", file: "settings.json", matcher: ""},
	"codex":  {agent: "Codex", dir: ".codex", file: "hooks.json", matcher: "^(Bash|apply_patch)$"},
}

// orderedObject keeps a JSON object's keys in file order so editing one key
// does not reshuffle the rest of the user's settings.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseObject(data []byte) (*orderedObject, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("top level must be a JSON object")
	}
	obj := &orderedObject{vals: map[string]json.RawMessage{}}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if _, dup := obj.vals[key]; !dup {
			obj.keys = append(obj.keys, key)
		}
		obj.vals[key] = raw
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON object")
	}
	return obj, nil
}

func (o *orderedObject) set(key string, raw json.RawMessage) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = raw
}

func (o *orderedObject) compact() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

type settingsHookGroup struct {
	Hooks []struct {
		Command string `json:"command"`
	} `json:"hooks"`
}

func isPolicycheckCommand(cmd string) bool {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	return filepath.Base(strings.Trim(fields[0], `"'`)) == "policycheck"
}

// hookCommand is what the agent will run: plain "policycheck" when that name
// resolves to this binary on PATH, otherwise this binary's absolute path.
func hookCommand() string {
	exe, err := os.Executable()
	if err != nil {
		return "policycheck"
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if lp, err := exec.LookPath("policycheck"); err == nil {
		if resolved, err := filepath.EvalSymlinks(lp); err == nil && resolved == exe {
			return "policycheck"
		}
	}
	if strings.ContainsAny(exe, " \t") {
		return `"` + exe + `"`
	}
	return exe
}

// addHook returns settings JSON with the policycheck PreToolUse hook added,
// and whether it was already there.
func addHook(existing []byte, matcher, command string) (out []byte, already bool, err error) {
	top := &orderedObject{vals: map[string]json.RawMessage{}}
	if len(bytes.TrimSpace(existing)) > 0 {
		if top, err = parseObject(existing); err != nil {
			return nil, false, err
		}
	}
	hooks := &orderedObject{vals: map[string]json.RawMessage{}}
	if raw, ok := top.vals["hooks"]; ok {
		if hooks, err = parseObject(raw); err != nil {
			return nil, false, fmt.Errorf(`"hooks": %w`, err)
		}
	}
	var groups []json.RawMessage
	if raw, ok := hooks.vals["PreToolUse"]; ok {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, false, fmt.Errorf(`"hooks.PreToolUse" must be an array: %w`, err)
		}
	}
	for _, g := range groups {
		var sg settingsHookGroup
		if json.Unmarshal(g, &sg) != nil {
			continue
		}
		for _, h := range sg.Hooks {
			if h.Command == command || isPolicycheckCommand(h.Command) {
				return existing, true, nil
			}
		}
	}

	type hookCmd struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	}
	entry, _ := json.Marshal(struct {
		Matcher string    `json:"matcher"`
		Hooks   []hookCmd `json:"hooks"`
	}{matcher, []hookCmd{{"command", command}}})
	groups = append(groups, entry)
	gb, _ := json.Marshal(groups)
	hooks.set("PreToolUse", gb)
	top.set("hooks", hooks.compact())

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, top.compact(), "", "  "); err != nil {
		return nil, false, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), false, nil
}

func initUsage() {
	fmt.Fprintln(os.Stderr, "usage: policycheck init claude|codex [--user] [--dry-run]")
	os.Exit(1)
}

// cmdInit adds the policycheck PreToolUse hook to Claude Code's or Codex's
// settings, keeping everything else in the file.
func cmdInit(args []string) {
	var agent string
	user, dry := false, false
	for _, a := range args {
		switch a {
		case "--user":
			user = true
		case "--dry-run":
			dry = true
		default:
			if agent != "" || strings.HasPrefix(a, "-") {
				initUsage()
			}
			agent = a
		}
	}
	target, ok := initTargets[agent]
	if !ok {
		fmt.Fprintf(os.Stderr, "policycheck init: unknown agent %q (use claude or codex)\n", agent)
		initUsage()
	}

	base := "."
	if user {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "policycheck init: %v\n", err)
			os.Exit(1)
		}
		base = home
	}
	file := filepath.Join(base, target.dir, target.file)

	existing, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "policycheck init: %v\n", err)
		os.Exit(1)
	}
	out, already, err := addHook(existing, target.matcher, hookCommand())
	if err != nil {
		fmt.Fprintf(os.Stderr, "policycheck init: %s is not usable, left unchanged: %v\n", file, err)
		os.Exit(1)
	}
	if already {
		fmt.Printf("The policycheck hook is already configured in %s\n", file)
		return
	}
	if dry {
		fmt.Printf("Would write %s:\n%s", file, out)
		return
	}

	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "policycheck init: %v\n", err)
		os.Exit(1)
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err == nil {
		err = os.Rename(tmp, file)
	}
	if err != nil {
		os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "policycheck init: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Added the policycheck hook to %s\n", file)
	if agent == "codex" {
		fmt.Println("Review and trust the hook with /hooks in the Codex CLI (or Settings > Hooks in the desktop app).")
	} else {
		fmt.Println("Restart Claude Code, or run /hooks, so it picks the hook up.")
	}
	fmt.Println(`Check the binary any time with: echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | policycheck`)
}
