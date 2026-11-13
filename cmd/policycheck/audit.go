package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"time"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func versionString() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

type auditEntry struct {
	Time       string      `json:"time"`
	Tool       string      `json:"tool"`
	Decision   string      `json:"decision"`
	Command    string      `json:"command,omitempty"`
	FilePath   string      `json:"file_path,omitempty"`
	URL        string      `json:"url,omitempty"`
	Path       string      `json:"path,omitempty"`
	Pattern    string      `json:"pattern,omitempty"`
	Glob       string      `json:"glob,omitempty"`
	Violations []violation `json:"violations"`
}

// writeAudit appends a JSON line to $POLICYCHECK_AUDIT_LOG for every call that
// matched at least one policy (blocked, or allowed only because of an ignore).
// Failures here only warn: logging must never change the decision.
// decision is "allow", "ask" or "block".
func writeAudit(toolName string, in toolInput, violations []violation, decision string) {
	path := os.Getenv("POLICYCHECK_AUDIT_LOG")
	if path == "" || len(violations) == 0 {
		return
	}

	line, err := json.Marshal(auditEntry{
		Time:       time.Now().UTC().Format(time.RFC3339),
		Tool:       toolName,
		Decision:   decision,
		Command:    in.Command,
		FilePath:   in.FilePath,
		URL:        in.URL,
		Path:       in.Path,
		Pattern:    in.Pattern,
		Glob:       in.Glob,
		Violations: violations,
	})
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, err = f.Write(append(line, '\n'))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write audit log: %v\n", err)
	}
}
