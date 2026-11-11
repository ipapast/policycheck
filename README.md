# cedar-policies

[![test](https://github.com/ipapast/cedar-policies/actions/workflows/test.yml/badge.svg)](https://github.com/ipapast/cedar-policies/actions/workflows/test.yml)

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
go install github.com/ipapast/cedar-policies/cmd/policycheck@latest
git clone https://github.com/ipapast/cedar-policies.git
```

`go install` puts `policycheck` in `~/go/bin/`. Make sure it's on your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

The binary does not embed the policies, so you need the clone too. Point the hook at its `policies/` directory.

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

Use an absolute path to the `policies/` directory in your clone. If the binary can't load the policies or can't parse its input, it exits 2 and blocks the tool call (fail closed), so a wrong path shows up immediately instead of silently disabling the guardrails.

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

## Included policies

| ID | Blocks |
|---|---|
| `CMD-001` | rm -r/-rf on dangerous paths (/, ~, *) |
| `CMD-002` | find -delete on dangerous paths (rm -rf bypass) |
| `CMD-003` | sudo/su/doas privilege escalation |
| `CMD-004` | chmod 777 and recursive chown |
| `CMD-005` | privileged Docker containers |
| `CMD-006` | kill -9 |
| `CMD-007` | disk-level commands (dd, mkfs, fdisk, parted) |
| `DATA-001` | environment variable dumping |
| `DATA-002` | reading credential and cloud config files |
| `DATA-003` | reading .env files |
| `DATA-004` | writing to shell config and dotfiles |
| `DATA-005` | reading system authentication files |
| `DATA-006` | searching credential and secret files with Glob/Grep |
| `NET-001` | piping downloads to shell execution |
| `NET-002` | data exfiltration via curl/wget POST |
| `NET-003` | accessing cloud metadata endpoints (SSRF risk) |
| `NET-004` | WebFetch to localhost, private network and internal URLs |
| `TOOL-001` | git force push |
| `TOOL-002` | modifying git remotes |
| `TOOL-003` | destructive git operations |
| `TOOL-004` | package publishing |
| `TOOL-005` | writing to CI/CD workflows |
| `TOOL-006` | editing agent settings and security files |
| `TOOL-007` | sending Slack messages via MCP |
| `TOOL-009` | pushing directly to main or master |
| `TOOL-010` | aws iam permission changes |
| `TOOL-011` | aws s3 mass deletion |
| `TOOL-012` | cdk deploy/destroy |
| `TOOL-013` | destructive psql commands (DROP, TRUNCATE) |

Policies in `examples/` are not loaded by default. They need a tweak for your setup (for example `TOOL-008` restricts `git push` to one GitHub account, so set your own username and copy it into `policies/`).

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

## Limitations

This is a guardrail, not a sandbox. Rules are glob matches on the command string or file path, not a parse of what the shell will actually do.

To make that harder to dodge, Bash commands are checked in several forms: as typed, with whitespace collapsed, and split into sub-commands (`;`, `&&`, `||`, `|`, newlines, `$(...)`, backticks). Leading env assignments and wrappers like `nohup`, `exec` and `env` are stripped, `/bin/rm` and `\rm` are treated as `rm`, and any recursive `rm` (`-r`, `-R`, `-fr`, `--recursive`) is rewritten to `rm -rf`. If several policies match, all of them are reported.

It still cannot see through variable expansion, `eval`, base64-encoded payloads, scripts that do the dangerous thing internally, or `cd` followed by relative paths. Named git remotes are not resolved. Treat the policies as a safety net for mistakes and obvious bad behavior, and use real isolation for anything critical. See [SECURITY.md](SECURITY.md).

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
| `context.url` | `tool_input.url` (WebFetch) | `"http://169.254.169.254/"` |
| `context.path` | `tool_input.path` (Glob/Grep) | `"/Users/me/.ssh"` |
| `context.pattern` | `tool_input.pattern` (Glob/Grep) | `"**/*.pem"` |
| `context.glob` | `tool_input.glob` (Grep) | `"*.env"` |

Fields are only present when the tool sends them, so guard optional ones with `context has path && ...` in a rule that can match several tools.

Action is the tool name: `Action::"Bash"`, `Action::"Read"`, `Action::"Write"`, `Action::"mcp__slack__slack_post_message"`, etc.

Every policy ships with a `*_test.json` file next to it listing tool calls and whether they should be blocked or allowed. Run them all with:

```bash
go test ./...
```

## Contributing

Add a failing test case first, then the policy that makes it pass:

1. Add cases to `policies/<area>/<ID>_test.json` (or create a new one) with `"expect": "block"` / `"allow"`.
2. Run `go test ./...` and confirm the new cases fail.
3. Write or update the `.cedar` file until they pass.

[`.claude/skills/writing-cedar-policies/SKILL.md`](.claude/skills/writing-cedar-policies/SKILL.md) describes this workflow in more detail and is also usable as a Claude Code skill.

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

Ignoring a policy also ignores its lettered variants, so `ignore DATA-002` covers `DATA-002b` (the Bash version of the same rule).

Options: `--reason` (optional), `--path` (scope to calls that touch this directory or something inside it, matched on whole path segments, so `/tmp` covers `/tmp/x` but not `/tmpfoo` or `/home/me/tmp-secrets`), `--expires` (default: 1 week from now).

Ignores are stored in `.cedar-ignores.json` in the current directory. This file is personal and should not be committed. Add it to your project's `.gitignore`:

```
.cedar-ignores.json
```

Or to your global gitignore (`git config --global core.excludesfile`) to cover all repos.

When an ignored policy would have blocked, it logs `IGNORED [CMD-001]: ...` to stderr so you still have visibility.

## Audit log

Set `POLICYCHECK_AUDIT_LOG` to a file path and every call that matched a policy is appended as one JSON line, including calls that were allowed only because of an ignore:

```bash
export POLICYCHECK_AUDIT_LOG=~/.local/state/policycheck/audit.jsonl
```

```json
{"time":"2026-03-09T09:43:00Z","tool":"Bash","decision":"block","command":"rm -rf /opt","violations":[{"id":"CMD-001","msg":"rm -r/-rf on dangerous paths (/, ~, *) is not allowed"}]}
```

Allowed calls that matched nothing are not logged. The file is created with mode 0600 because commands and paths may contain sensitive values. If the log can't be written, `policycheck` prints a warning and still enforces the policies.

## Versions

`policycheck --version` prints the version. Binaries installed with `go install ...@v1.2.3` report that tag; builds from a checkout report a commit-based version (or `dev` outside a git checkout). Pass `-ldflags "-X main.version=..."` to set one explicitly.

## What else can be checked

Claude Code sends a `tool_name` and `tool_input` for every tool call. Bash (`command`), Read/Write/Edit (`file_path`), WebFetch (`url`) and Glob/Grep (`path`, `pattern`, `glob`) are mapped into the context. Tools you could still write policies for:

- `Agent` - sends `{"prompt": "...", "subagent_type": "..."}` - restrict which subagent types can run
- `WebSearch` - sends `{"query": "..."}` - restrict search queries
- `NotebookEdit` - sends `{"notebook_path": "...", ...}` - same concerns as Write but for notebooks
- MCP tools - any `mcp__*` tool can be matched by action name, with or without checking input fields

To use a new `tool_input` field in Cedar context, add it to the `toolInput` struct and to `buildContext` in `cmd/policycheck/eval.go`. The test runner picks it up automatically.

## Files

```
cedar-policies/
  cmd/policycheck/
    main.go            # hook binary, ignores
    eval.go            # command normalization and evaluation
    audit.go           # audit log and version
    main_test.go       # test runner (loads *_test.json files)
  examples/            # policies that need customizing before use
  policies/
    base.cedar         # default permit rules
    cmd/               # dangerous commands (rm, sudo, chmod, docker, kill)
    data/              # secrets, credentials, dotfiles
    net/               # network exfiltration
    tool/              # git, MCP, CI/CD, package publishing
  SECURITY.md
  LICENSE              # Apache-2.0
  go.mod
  go.sum
```

## License

Apache-2.0. See [LICENSE](LICENSE).
