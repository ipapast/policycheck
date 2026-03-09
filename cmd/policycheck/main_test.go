package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

type testCase struct {
	Name      string         `json:"name"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Expect    string         `json:"expect"` // "allow" or "block"
}

func TestPolicies(t *testing.T) {
	ps, err := loadPolicies("../../policies")
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	var testFiles []string
	filepath.Walk("../../policies", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			testFiles = append(testFiles, path)
		}
		return nil
	})
	if len(testFiles) == 0 {
		t.Fatal("no test files found")
	}

	for _, tf := range testFiles {
		data, err := os.ReadFile(tf)
		if err != nil {
			t.Fatalf("failed to read %s: %v", tf, err)
		}

		var cases []testCase
		if err := json.Unmarshal(data, &cases); err != nil {
			t.Fatalf("failed to parse %s: %v", tf, err)
		}

		for _, tc := range cases {
			t.Run(tc.Name, func(t *testing.T) {
				context := cedar.RecordMap{}
				if cmd, ok := tc.ToolInput["command"].(string); ok && cmd != "" {
					context["command"] = cedar.String(cmd)
				}
				if fp, ok := tc.ToolInput["file_path"].(string); ok && fp != "" {
					context["file_path"] = cedar.String(fp)
				}

				req := cedar.Request{
					Principal: cedar.NewEntityUID("Agent", "claude"),
					Action:    cedar.NewEntityUID("Action", cedar.String(tc.ToolName)),
					Resource:  cedar.NewEntityUID("Resource", "tool_call"),
					Context:   cedar.NewRecord(context),
				}

				decision, _ := ps.IsAuthorized(cedar.EntityMap{}, req)

				if tc.Expect == "block" && decision != cedar.Deny {
					t.Errorf("expected block, got allow")
				}
				if tc.Expect == "allow" && decision == cedar.Deny {
					t.Errorf("expected allow, got block")
				}
			})
		}
	}
}
