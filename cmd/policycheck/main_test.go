package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

func TestPolicies(t *testing.T) {
	ps := cedar.NewPolicySet()
	var testFiles []string
	for _, dir := range []string{"../../policies", "../../examples"} {
		dirPS, err := loadPolicies(dir)
		if err != nil {
			t.Fatalf("failed to load policies from %s: %v", dir, err)
		}
		for id, p := range dirPS.All() {
			ps.Add(id, p)
		}
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && filepath.Ext(path) == ".json" {
				testFiles = append(testFiles, path)
			}
			return nil
		})
	}
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
				if err := checkCase(ps, tc); err != nil {
					t.Error(err)
				}
			})
		}
	}
}
