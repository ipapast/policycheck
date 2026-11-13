# Writing and testing policies

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
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test"}}' | policycheck

# Should allow
echo '{"tool_name":"Bash","tool_input":{"command":"go test ./..."}}' | policycheck
```

These use the built-in policies. When you are editing policies in a clone, pass the directory so you test your edits: `policycheck ./policies`.

## Context fields

The hook input is mapped to Cedar context:

| Field | Source | Example |
|---|---|---|
| `context.command` | `tool_input.command` (Bash) | `"rm -rf /tmp"` |
| `context.file_path` | `tool_input.file_path` (Read/Write/Edit) | `"~/.ssh/id_rsa"` |
| `context.url` | `tool_input.url` (WebFetch) | `"http://169.254.169.254/"` |
| `context.path` | `tool_input.path` (Glob/Grep) | `"/Users/me/.ssh"` |
| `context.pattern` | `tool_input.pattern` (Glob/Grep) | `"**/*.pem"` |
| `context.glob` | `tool_input.glob` (Grep) | `"*.env"` |

Fields are only present when the tool sends them, so guard optional ones with `context has path && ...` in a rule that can match several tools.

For Codex `apply_patch`, each affected file is additionally evaluated as both `Write` and `Edit`, with an absolute `context.file_path`. Existing symlinks are resolved and checked too. See [Codex file edits](agents.md#file-edits).

Action is the tool name: `Action::"Bash"`, `Action::"Read"`, `Action::"Write"`, `Action::"mcp__slack__slack_post_message"`, etc.

Every policy ships with a `*_test.json` file next to it listing tool calls and whether they should be blocked or allowed. Run them all with the binary, no Go needed:

```bash
policycheck test ./policies    # your own policy directory
policycheck test               # the built-in policies
```

It prints each failing case with its file and exits 1 if any fail, so it works in CI. Inside a clone of this repo, `go test ./...` runs the same fixtures plus the Go tests. A fixture file is a JSON array of `{"name", "tool_name", "tool_input", "expect"}` objects, where `expect` is `"allow"` or `"block"`. Your policy directory needs a permit policy like `policies/base.cedar`, because Cedar denies everything that no `permit` covers.

## What else can be checked

Claude Code sends a `tool_name` and `tool_input` for every tool call. Bash (`command`), Read/Write/Edit (`file_path`), WebFetch (`url`) and Glob/Grep (`path`, `pattern`, `glob`) are mapped into the context. Tools you could still write policies for:

- `Agent` - sends `{"prompt": "...", "subagent_type": "..."}` - restrict which subagent types can run
- `WebSearch` - sends `{"query": "..."}` - restrict search queries
- `NotebookEdit` - sends `{"notebook_path": "...", ...}` - same concerns as Write but for notebooks
- MCP tools - any `mcp__*` tool can be matched by action name, with or without checking input fields

To use a new `tool_input` field in Cedar context, add it to the `toolInput` struct and to `buildContext` in `cmd/policycheck/eval.go`. The test runner picks it up automatically.

## Contributing

Add a failing test case first, then the policy that makes it pass:

1. Add cases to `policies/<area>/<ID>_test.json` (or create a new one) with `"expect": "block"` / `"allow"`.
2. Run `go test ./...` and confirm the new cases fail.
3. Write or update the `.cedar` file until they pass.

[`.claude/skills/writing-cedar-policies/SKILL.md`](../.claude/skills/writing-cedar-policies/SKILL.md) describes this workflow in more detail and is also usable as a Claude Code skill.

## Files

```
policycheck/
  policies.go          # embeds policies/ into the binary
  cmd/policycheck/
    main.go            # hook binary, ignores
    eval.go            # command normalization and evaluation
    audit.go           # audit log and version
    patch.go           # Codex patch targets and file-policy checks
    main_test.go       # test runner (loads *_test.json files)
    *_test.go          # exit codes, audit log, ignores, embedded policies
  examples/            # policies that need customizing before use
  policies/
    base.cedar         # default permit rules
    cmd/               # dangerous commands (rm, sudo, chmod, docker, kill)
    data/              # secrets, credentials, dotfiles
    net/               # network exfiltration
    tool/              # git, MCP, CI/CD, package publishing
  docs/                # usage, writing policies, dev containers, other agents
  SECURITY.md
  LICENSE              # Apache-2.0
  go.mod
  go.sum
```
