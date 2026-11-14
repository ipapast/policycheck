package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cedar-policy/cedar-go"
	cedarpolicies "github.com/ipapast/policycheck"
)

type testCase struct {
	Name      string         `json:"name"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Expect    string         `json:"expect"` // "allow" or "block"
}

// checkCase evaluates one fixture case and returns an error describing any
// mismatch with its expected outcome.
func checkCase(ps *cedar.PolicySet, tc testCase) error {
	if tc.Expect != "allow" && tc.Expect != "block" {
		return fmt.Errorf("expect must be \"allow\" or \"block\", got %q", tc.Expect)
	}
	var in toolInput
	raw, _ := json.Marshal(tc.ToolInput)
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("bad tool_input: %w", err)
	}
	blocked := len(evaluate(ps, tc.ToolName, in)) > 0
	switch {
	case tc.Expect == "block" && !blocked:
		return fmt.Errorf("expected block, got allow")
	case tc.Expect == "allow" && blocked:
		return fmt.Errorf("expected allow, got block")
	}
	return nil
}

// runFixtures runs every *_test.json under root in fsys against ps. It returns
// the number of files and passing cases, plus one message per problem.
func runFixtures(fsys fs.FS, root string, ps *cedar.PolicySet) (files, passed int, problems []string) {
	walkErr := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.json") {
			return nil
		}
		files++
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		var cases []testCase
		if err := json.Unmarshal(data, &cases); err != nil {
			problems = append(problems, fmt.Sprintf("%s: invalid JSON: %v", path, err))
			return nil
		}
		for _, tc := range cases {
			if err := checkCase(ps, tc); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %s: %v", path, tc.Name, err))
			} else {
				passed++
			}
		}
		return nil
	})
	if walkErr != nil {
		problems = append(problems, walkErr.Error())
	}
	return files, passed, problems
}

func hasPermitPolicy(ps *cedar.PolicySet) bool {
	for _, p := range ps.All() {
		if p.Effect() == cedar.Permit {
			return true
		}
	}
	return false
}

// cmdTest runs the *_test.json fixtures that sit next to the policies and
// exits 1 if any case fails. With no directory it tests the built-in policies.
func cmdTest(args []string) {
	var (
		ps    *cedar.PolicySet
		fsys  fs.FS
		root  string
		label string
		err   error
	)
	if len(args) > 0 {
		root, label = args[0], args[0]
		fsys = os.DirFS(root)
		ps, err = loadPolicies(root)
		root = "."
	} else {
		fsys, root, label = cedarpolicies.FS, "policies", "built-in policies"
		ps, err = loadEmbeddedPolicies()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "policycheck test: %v\n", err)
		os.Exit(1)
	}

	if !hasPermitPolicy(ps) {
		fmt.Fprintf(os.Stderr, "warning: no permit policy found in %s. Cedar denies everything that no permit policy allows, so every \"allow\" case will fail. Add a permit policy such as policies/base.cedar.\n", label)
	}

	files, passed, problems := runFixtures(fsys, root, ps)
	if files == 0 {
		fmt.Fprintf(os.Stderr, "policycheck test: no *_test.json files found in %s\n", label)
		os.Exit(1)
	}
	for _, p := range problems {
		fmt.Printf("FAIL %s\n", filepath.ToSlash(p))
	}
	fmt.Printf("%s: %d files, %d passed, %d failed\n", label, files, passed, len(problems))
	if len(problems) > 0 {
		os.Exit(1)
	}
}
