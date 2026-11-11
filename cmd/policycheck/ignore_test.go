package main

import "testing"

func TestIsIgnoredCoversSuffixedVariants(t *testing.T) {
	cases := []struct {
		ignored, blocked string
		want             bool
	}{
		{"DATA-002", "DATA-002", true},
		{"DATA-002", "DATA-002b", true},
		{"DATA-004", "DATA-004c", true},
		{"TOOL-007", "TOOL-007e", true},
		{"DATA-002b", "DATA-002b", true},
		{"DATA-002b", "DATA-002", false},
		{"DATA-002b", "DATA-002c", false},
		{"CMD-001", "CMD-0010", false},
		{"CMD-001", "CMD-001-extra", false},
		{"CMD-001", "CMD-002", false},
	}
	for _, tc := range cases {
		ignores := []ignoreEntry{{Policy: tc.ignored}}
		got := isIgnored(tc.blocked, ignores, toolInput{}) != nil
		if got != tc.want {
			t.Errorf("ignore %s vs blocked %s: got %v, want %v", tc.ignored, tc.blocked, got, tc.want)
		}
	}
}

func TestIsIgnoredPathScopeUsesPathBoundaries(t *testing.T) {
	cases := []struct {
		name, scope, command, filePath string
		want                           bool
	}{
		{"command arg inside dir", "/tmp", "rm -rf /tmp/x", "", true},
		{"command arg equals dir", "/tmp", "rm -rf /tmp", "", true},
		{"flag value inside dir", "/tmp", "cp a --out=/tmp/x", "", true},
		{"file inside dir", "/tmp", "", "/tmp/a/b", true},
		{"trailing slash on scope", "/tmp/", "rm -rf /tmp/x", "", true},
		{"similar prefix is not inside", "/tmp", "rm -rf /tmpfoo/x", "", false},
		{"substring elsewhere is not inside", "/tmp", "rm -rf /home/x/tmp-secrets", "", false},
		{"substring dir elsewhere is not inside", "/tmp", "rm -rf /home/x/tmp/y", "", false},
		{"file with similar prefix", "/tmp", "", "/tmpfoo/a", false},
		{"unrelated input", "/tmp", "rm -rf /var/x", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ignores := []ignoreEntry{{Policy: "CMD-001", Path: tc.scope}}
			got := isIgnored("CMD-001", ignores, toolInput{Command: tc.command, FilePath: tc.filePath}) != nil
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
