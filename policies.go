// Package cedarpolicies embeds the default policy set so a single binary can
// enforce it with no policies directory on disk.
package cedarpolicies

import "embed"

// FS holds the default *.cedar files and their *_test.json fixtures under
// "policies/", so "policycheck test" can check the built-in policies. examples/
// is not embedded.
//
//go:embed policies/*.cedar policies/*/*.cedar policies/*/*_test.json
var FS embed.FS
