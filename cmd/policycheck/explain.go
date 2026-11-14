package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	cedarpolicies "github.com/ipapast/policycheck"
)

type ruleInfo struct {
	ID       string
	Msg      string
	Decision string
	Source   string
	Dir      string
}

// collectRules reads every forbid rule under root in fsys.
func collectRules(fsys fs.FS, root string) ([]ruleInfo, error) {
	var rules []ruleInfo
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".cedar" {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		var pl cedar.PolicyList
		if err := pl.UnmarshalCedar(data); err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		for i, pol := range pl {
			if pol.Effect() != cedar.Forbid {
				continue
			}
			info := ruleInfo{ID: fmt.Sprintf("%s#%d", path.Base(p), i), Dir: path.Dir(p), Decision: "block"}
			if ann := pol.Annotations(); ann != nil {
				if v, ok := ann[types.Ident("id")]; ok {
					info.ID = string(v)
				}
				info.Msg = string(ann[types.Ident("msg")])
				if string(ann[types.Ident("decision")]) == "ask" {
					info.Decision = "ask"
				}
			}
			info.Source = strings.TrimSpace(string(pol.MarshalCedar()))
			rules = append(rules, info)
		}
		return nil
	})
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, err
}

type fixtureLine struct{ Expect, Name string }

func readFixture(fsys fs.FS, dir, id string) (string, []fixtureLine) {
	file := path.Join(dir, id+"_test.json")
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", nil
	}
	var cases []testCase
	if json.Unmarshal(data, &cases) != nil {
		return "", nil
	}
	lines := make([]fixtureLine, 0, len(cases))
	for _, c := range cases {
		lines = append(lines, fixtureLine{c.Expect, c.Name})
	}
	return path.Base(file), lines
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

// cmdExplain prints what a rule does: its message, source and test cases.
// "policycheck explain" lists every rule; "policycheck explain ID [dir]" shows
// one rule and its variants (ID plus lowercase suffixes such as DATA-002b).
func cmdExplain(args []string) {
	var (
		fsys fs.FS = cedarpolicies.FS
		root       = "policies"
	)
	listOnly := len(args) == 0 || args[0] == "--list"
	var id, dir string
	switch {
	case len(args) == 0:
	case args[0] == "--list":
		if len(args) > 1 {
			dir = args[1]
		}
	default:
		id = args[0]
		if len(args) > 1 {
			dir = args[1]
		}
	}
	if dir != "" {
		if _, err := os.Stat(dir); err != nil {
			fmt.Fprintf(os.Stderr, "policycheck explain: %v\n", err)
			os.Exit(1)
		}
		fsys, root = os.DirFS(dir), "."
	}

	rules, err := collectRules(fsys, root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policycheck explain: %v\n", err)
		os.Exit(1)
	}

	if listOnly {
		for _, r := range rules {
			fmt.Printf("%-10s %-6s %s\n", r.ID, r.Decision, r.Msg)
		}
		return
	}

	shown := 0
	for _, r := range rules {
		if !policyMatches(id, r.ID) {
			continue
		}
		if shown > 0 {
			fmt.Println()
		}
		shown++
		verb := "blocks"
		if r.Decision == "ask" {
			verb = "asks before running"
		}
		fmt.Printf("%s (%s)\n", r.ID, verb)
		if r.Msg != "" {
			fmt.Printf("  %s\n", r.Msg)
		}
		fmt.Printf("\n%s\n", indent(r.Source, "  "))
		if file, cases := readFixture(fsys, r.Dir, r.ID); len(cases) > 0 {
			fmt.Printf("\n  Test cases (%s):\n", file)
			for _, c := range cases {
				fmt.Printf("    %-5s  %s\n", c.Expect, c.Name)
			}
		}
	}
	if shown == 0 {
		fmt.Fprintf(os.Stderr, "policycheck explain: no rule with ID %s. Run \"policycheck explain\" to list them.\n", id)
		os.Exit(1)
	}
}
