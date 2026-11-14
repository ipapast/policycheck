package main

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

type toolInput struct {
	Command  string `json:"command"`
	FilePath string `json:"file_path"`
	URL      string `json:"url"`
	Path     string `json:"path"`
	Pattern  string `json:"pattern"`
	Glob     string `json:"glob"`
}

type violation struct {
	ID       string `json:"id"`
	Msg      string `json:"msg,omitempty"`
	Ignored  bool   `json:"ignored,omitempty"`
	Decision string `json:"decision,omitempty"`
	FilePath string `json:"file_path,omitempty"`
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
	return commandVariantsDepth(cmd, 0)
}

const maxShellNesting = 4

func commandVariantsDepth(cmd string, depth int) []string {
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
	if depth < maxShellNesting {
		for _, inner := range innerShellCommands(cmd) {
			for _, v := range commandVariantsDepth(inner, depth+1) {
				add(v)
			}
		}
	}
	return out
}

var shellNames = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
}

var shellCFlag = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

// innerShellCommands returns the command strings that cmd hands to another
// shell: the argument of "bash -c" (and sh, zsh, dash, ksh) and the arguments
// of "eval". They are evaluated like any other command, so wrapping a command
// in a shell does not hide it.
func innerShellCommands(cmd string) []string {
	words := shellWords(cmd)
	var out []string
	for i, w := range words {
		name := strings.TrimPrefix(w, `\`)
		name = name[strings.LastIndex(name, "/")+1:]
		switch {
		case name == "eval" && i+1 < len(words):
			out = append(out, strings.Join(words[i+1:], " "))
		case shellNames[name]:
			for j := i + 1; j < len(words) && strings.HasPrefix(words[j], "-"); j++ {
				if shellCFlag.MatchString(words[j]) {
					if j+1 < len(words) {
						out = append(out, words[j+1])
					}
					break
				}
			}
		}
	}
	return out
}

// shellWords splits s into words the way a shell would for our purposes:
// quotes group text and are removed, a backslash escapes the next character
// outside single quotes, and unquoted ; | & ( ) end a word.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			switch {
			case r == quote:
				quote = 0
			case r == '\\' && quote == '"' && i+1 < len(rs):
				i++
				cur.WriteRune(rs[i])
			default:
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == '\\' && i+1 < len(rs):
			i++
			cur.WriteRune(rs[i])
			inWord = true
		case r == ' ' || r == '\t' || r == '\n' || r == ';' || r == '|' || r == '&' || r == '(' || r == ')':
			flush()
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return words
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

func buildContext(in toolInput) cedar.Record {
	ctx := cedar.RecordMap{}
	for k, v := range map[string]string{
		"command":   in.Command,
		"file_path": in.FilePath,
		"url":       in.URL,
		"path":      in.Path,
		"pattern":   in.Pattern,
		"glob":      in.Glob,
	} {
		if v != "" {
			ctx[cedar.String(k)] = cedar.String(v)
		}
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
		variant := in
		variant.Command = c
		req := cedar.Request{
			Principal: cedar.NewEntityUID("Agent", "claude"),
			Action:    cedar.NewEntityUID("Action", cedar.String(toolName)),
			Resource:  cedar.NewEntityUID("Resource", "tool_call"),
			Context:   buildContext(variant),
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
	return policyAnnotation(ps, id, "msg")
}

func policyAnnotation(ps *cedar.PolicySet, id, key string) string {
	for pid, p := range ps.All() {
		if string(pid) != id {
			continue
		}
		if ann := p.Annotations(); ann != nil {
			if v, ok := ann[types.Ident(key)]; ok {
				return string(v)
			}
		}
	}
	return ""
}
