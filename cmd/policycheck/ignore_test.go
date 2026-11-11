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
		got := isIgnored(tc.blocked, ignores, "", "") != nil
		if got != tc.want {
			t.Errorf("ignore %s vs blocked %s: got %v, want %v", tc.ignored, tc.blocked, got, tc.want)
		}
	}
}
