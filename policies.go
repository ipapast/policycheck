// Package cedarpolicies embeds the default policy set so a single binary can
// enforce it with no policies directory on disk.
package cedarpolicies

import "embed"

// FS holds the default *.cedar files under "policies/". Test fixtures and
// examples/ are not embedded.
//
//go:embed policies/*.cedar policies/*/*.cedar
var FS embed.FS
