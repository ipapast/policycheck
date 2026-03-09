# cedar-policies

Cedar policy engine for AI coding agents - testable, named security rules for tool-use guardrails.

Built on [Cedar](https://docs.cedarpolicy.com/), AWS's open-source policy language.

## How it works

```
Agent tool call
  -> pre-execution hook fires
  -> policycheck reads JSON from stdin
  -> evaluates Cedar policies
  -> exit 0 (allow) or exit 2 (block with ID + message)
```

The input is a JSON object with `tool_name` and `tool_input` fields. Any agent framework that can pipe tool calls through a hook can use this.

## Quick start

Requires Go 1.24+.

```bash
go install ./cmd/policycheck
```

This installs `policycheck` to `~/go/bin/`. Make sure it's on your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Claude Code

Add to your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "policycheck /path/to/cedar-policies/policies"
          }
        ]
      }
    ]
  }
}
```

### Other agents

Pipe tool calls as JSON to stdin before execution:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | ./policycheck ./policies
# exit 2 = blocked, exit 0 = allowed
```

## Cedar 101

Cedar is a policy language by AWS. Every request has a **principal** (who), **action** (what tool), and **resource** (target), plus a **context** with extra data.

- `permit` allows, `forbid` denies - **forbid always wins**
- If nothing permits a request, it's denied (default-deny)
- `like` is the only pattern operator: `*` matches any string, no regex
- All rules are evaluated, not just the first match

Our `base.cedar` permits everything by default. Individual policy files add `forbid` rules that override.

For the full language reference, see the [Cedar docs](https://docs.cedarpolicy.com/).

## Writing policies

Policies are Cedar files in the `policies/` directory. Each forbid rule needs `@id` and `@msg` annotations:

```cedar
@id("CMD-001")
@msg("rm -r/-rf on dangerous paths (/, ~, *) is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "rm -rf /*"
};
```

### Policy naming

| Prefix | Scope | Examples |
|---|---|---|
| `CMD` | Dangerous commands | rm -rf, sudo, chmod 777, find -delete |
| `DATA` | Secrets and sensitive files | read ~/.ssh, env dump, credentials |
| `NET` | Network and exfiltration | curl POST, wget pipe, dns tunneling |
| `TOOL` | Tool-specific controls | MCP tools, package publishing, git force push |

Numbers are sequential within each prefix: `CMD-001`, `CMD-002`, `NET-001`, etc.

## Testing policies

```bash
# Should block
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test"}}' | ./policycheck ./policies

# Should allow
echo '{"tool_name":"Bash","tool_input":{"command":"go test ./..."}}' | ./policycheck ./policies
```

## Context fields

The hook input is mapped to Cedar context:

| Field | Source | Example |
|---|---|---|
| `context.command` | `tool_input.command` (Bash) | `"rm -rf /tmp"` |
| `context.file_path` | `tool_input.file_path` (Read/Write/Edit) | `"~/.ssh/id_rsa"` |

Action is the tool name: `Action::"Bash"`, `Action::"Read"`, `Action::"Write"`, `Action::"mcp__slack__slack_post_message"`, etc.

## Ignoring policies

You can temporarily suppress a policy per project. Default expiry is 1 week.

```bash
# Ignore a policy
./policycheck ignore CMD-001 --reason "cleanup script needs rm -rf"

# Ignore only for a specific path
./policycheck ignore CMD-001 --reason "cleanup script" --path "/tmp"

# Ignore with custom expiry
./policycheck ignore CMD-001 --reason "migration" --expires 2026-04-01

# List active ignores
./policycheck list-ignores

# Remove an ignore
./policycheck unignore CMD-001
```

Options: `--reason` (optional), `--path` (scope to commands/files matching this substring), `--expires` (default: 1 week from now).

Ignores are stored in `.cedar-ignores.json` in the current directory. This file is personal and should not be committed. Add it to your project's `.gitignore`:

```
.cedar-ignores.json
```

Or to your global gitignore (`git config --global core.excludesfile`) to cover all repos.

When an ignored policy would have blocked, it logs `IGNORED [CMD-001]: ...` to stderr so you still have visibility.

## What else can be checked

Claude Code sends a `tool_name` and `tool_input` for every tool call. Currently we check `command` (Bash) and `file_path` (Read/Write/Edit), but there are more tools you could write policies for:

- `Glob` - sends `{"pattern": "**/*.pem", "path": "/etc"}` - block glob patterns targeting sensitive directories
- `Grep` - sends `{"pattern": "password", "path": "...", "glob": "*.env"}` - block searching for secrets
- `Agent` - sends `{"prompt": "...", "subagent_type": "..."}` - restrict which subagent types can run
- `WebFetch` - sends `{"url": "https://...", "prompt": "..."}` - block fetching from internal URLs (read-only, no POST)
- `WebSearch` - sends `{"query": "..."}` - restrict search queries
- `NotebookEdit` - sends `{"notebook_path": "...", ...}` - same concerns as Write but for notebooks
- MCP tools - any `mcp__*` tool can be matched by action name, with or without checking input fields

To use new `tool_input` fields in Cedar context, add them to the `hookInput` struct in `main.go` and the corresponding context-building logic in both `cmdEvaluate` and `TestPolicies`.

## Files

```
cedar-policies/
  cmd/policycheck/
    main.go            # hook binary
    main_test.go       # test runner (loads *_test.json files)
  policies/
    base.cedar         # default permit rules
    cmd/               # dangerous commands (rm, sudo, chmod, docker, kill)
    data/              # secrets, credentials, dotfiles
    net/               # network exfiltration
    tool/              # git, MCP, CI/CD, package publishing
  go.mod
  go.sum
```
