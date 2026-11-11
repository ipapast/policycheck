package main

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

type toolInput struct {
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
}

type violation struct {
	ID  string
	Msg string
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var commandWrappers = map[string]bool{
	"command": true, "builtin": true, "exec": true, "nohup": true,
	"time": true, "nice": true, "env": true,
}

// commandVariants returns the forms of a Bash command that policies are
// evaluated against: the raw command, a whitespace-collapsed copy, and each
// sub-command (split on ; | & newlines, $( ) and backticks) in canonical form.
func commandVariants(cmd string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	add(cmd)
	add(strings.Join(strings.Fields(cmd), " "))

	segments := strings.FieldsFunc(cmd, func(r rune) bool {
		switch r {
		case ';', '|', '&', '\n', '`', '(', ')':
			return true
		}
		return false
	})
	for _, seg := range segments {
		add(canonicalSegment(seg))
	}
	return out
}

func canonicalSegment(seg string) string {
	tokens := strings.Fields(seg)

	for len(tokens) > 0 && envAssignment.MatchString(tokens[0]) {
		tokens = tokens[1:]
	}
	for len(tokens) > 1 && commandWrappers[unquoteWord(tokens[0])] {
		tokens = tokens[1:]
		for len(tokens) > 0 && envAssignment.MatchString(tokens[0]) {
			tokens = tokens[1:]
		}
	}
	if len(tokens) == 0 {
		return ""
	}

	name := strings.TrimPrefix(unquoteWord(tokens[0]), `\`)
	if strings.HasPrefix(name, "/") {
		name = name[strings.LastIndex(name, "/")+1:]
	}
	tokens[0] = name

	if name == "rm" {
		tokens = canonicalRm(tokens[1:])
	}
	return strings.Join(tokens, " ")
}

func unquoteWord(s string) string {
	return strings.Trim(s, `'"`)
}

// canonicalRm rewrites any recursive rm (-r, -R, -fr, --recursive, ...) to
// "rm -rf <args>" so one pattern covers every flag spelling.
func canonicalRm(args []string) []string {
	recursive := false
	var rest []string
	flagsDone := false
	for _, a := range args {
		switch {
		case flagsDone || !strings.HasPrefix(a, "-") || a == "-":
			rest = append(rest, a)
		case a == "--":
			flagsDone = true
		case a == "--recursive":
			recursive = true
		case strings.HasPrefix(a, "--"):
		default:
			if strings.ContainsAny(a, "rR") {
				recursive = true
			}
		}
	}
	if !recursive {
		return append([]string{"rm"}, args...)
	}
	return append([]string{"rm", "-rf"}, rest...)
}

func buildContext(command, filePath string) cedar.Record {
	ctx := cedar.RecordMap{}
	if command != "" {
		ctx["command"] = cedar.String(command)
	}
	if filePath != "" {
		ctx["file_path"] = cedar.String(filePath)
	}
	return cedar.NewRecord(ctx)
}

// evaluate returns every policy violated by the tool call, sorted by ID.
// Bash commands are checked in all their variants (see commandVariants).
func evaluate(ps *cedar.PolicySet, toolName string, in toolInput) []violation {
	commands := []string{in.Command}
	if toolName == "Bash" && in.Command != "" {
		commands = commandVariants(in.Command)
	}

	found := map[string]bool{}
	for _, c := range commands {
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Agent", "claude"),
			Action:    cedar.NewEntityUID("Action", cedar.String(toolName)),
			Resource:  cedar.NewEntityUID("Resource", "tool_call"),
			Context:   buildContext(c, in.FilePath),
		}
		decision, diag := ps.IsAuthorized(cedar.EntityMap{}, req)
		if decision != cedar.Deny {
			continue
		}
		if len(diag.Reasons) == 0 {
			found["unknown"] = true
		}
		for _, r := range diag.Reasons {
			found[string(r.PolicyID)] = true
		}
	}

	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]violation, 0, len(ids))
	for _, id := range ids {
		out = append(out, violation{ID: id, Msg: policyMessage(ps, id)})
	}
	return out
}

func policyMessage(ps *cedar.PolicySet, id string) string {
	for pid, p := range ps.All() {
		if string(pid) != id {
			continue
		}
		if ann := p.Annotations(); ann != nil {
			if v, ok := ann["msg"]; ok {
				return string(v)
			}
		}
	}
	return ""
}
