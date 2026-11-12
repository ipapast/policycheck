# cedar-policies

[![test](https://github.com/ipapast/cedar-policies/actions/workflows/test.yml/badge.svg)](https://github.com/ipapast/cedar-policies/actions/workflows/test.yml)

Tested, named security guardrails for [Claude Code](https://claude.com/claude-code) and [Codex](https://learn.chatgpt.com/docs/hooks), written as [Cedar](https://docs.cedarpolicy.com/) policies.

Claude Code's built-in permission rules decide what to allow. cedar-policies adds a layer on top: every rule has a stable ID and message, ships with unit tests, can be ignored per project with an expiry, and every block or ignore can be written to an audit log. It runs as a `PreToolUse` hook and covers Bash, file tools, Glob/Grep and WebFetch.

Tested with Claude Code and with Codex CLI for shell commands and native `apply_patch` edits. Patch targets are checked against the existing `Write` and `Edit` policies; see [Codex](#codex) for setup and tested scope.

This is a starting point. The rules cover common mistakes and obvious bad behavior, and they are meant to be read, changed and extended for your own setup.

## What it helps with

An agent with shell and file access can do real damage from one bad step. A prompt injection hidden in a README or a web page might tell it to "clean up" with `rm -rf`, "debug" by reading `~/.aws/credentials`, or "check connectivity" by calling the cloud metadata endpoint. A plain mistake can do the same thing without any attacker.

These policies sit in front of every tool call and stop the common cases:

- **Destructive commands:** `rm -rf` on broad paths, `sudo`, `chmod 777`, disk tools, `kill -9`
- **Secrets:** SSH and cloud credentials, `.env` files, `credentials.json`, `.npmrc`, kubeconfig, private keys, environment dumps
- **Exfiltration and SSRF:** piping downloads into a shell, POSTing data out with curl, fetching localhost or cloud metadata URLs
- **Risky workflows:** force pushes, pushing to main, editing CI workflows or the agent's own settings, package publishing, mass deletes in AWS and Postgres

## How it works

```
Agent tool call
  -> pre-execution hook fires
  -> policycheck reads JSON from stdin
  -> evaluates Cedar policies
  -> exit 0 (allow) or exit 2 (block with ID + message)
```

The input is a JSON object with `tool_name` and `tool_input` fields, in Claude Code's hook format.

`policycheck` is a single static binary. It needs no network, no daemon and no credentials, and it only reads the policy files you point it at and (optionally) writes an audit log.

## Use it with the built-in permissions and the sandbox

This is one layer, not the whole defense. The permission settings and sandbox details below describe Claude Code; keep Codex's own permissions and sandbox enabled too:

- **Permission rules** (`permissions.allow/ask/deny` in `settings.json`) are the first line. Keep using them. Their matching on command arguments is documented as fragile, which is where extra policies help.
- **Hooks like this one** can inspect the full tool input, for example a URL inside a Bash command, or Glob and Grep targets. A blocked call is stopped even if a permission rule would have allowed it.
- **The sandbox** is the only layer that enforces limits at the OS level, and it covers Bash only. Hooks run outside it, so enable the sandbox for anything that matters and treat these policies as an additional check, not a replacement.

See [SECURITY.md](SECURITY.md) for what pattern matching can and can't catch.

## Quick start

Requires Go 1.24+ to install.

```bash
go install github.com/ipapast/cedar-policies/cmd/policycheck@latest
```

`go install` puts `policycheck` in `~/go/bin/`. Make sure it's on your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

The default policies are compiled into the binary, so that one file is all you need. No clone, no policies directory.

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
            "command": "policycheck"
          }
        ]
      }
    ]
  }
}
```

If the binary can't load policies or can't parse its input, it exits 2 and blocks the tool call (fail closed), so a mistake shows up immediately instead of silently disabling the guardrails.

### Codex

Add this to `~/.codex/hooks.json` for all projects, or `<repo>/.codex/hooks.json` for one project:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|apply_patch)$",
        "hooks": [
          {
            "type": "command",
            "command": "policycheck"
          }
        ]
      }
    ]
  }
}
```

If `policycheck` is not on Codex's PATH, use its absolute path in `command`, for example `/Users/you/go/bin/policycheck`. Review and trust the hook through `/hooks` in the CLI or **Settings → Hooks** in the desktop app. Project-local hooks also require a trusted project. See the [Codex hooks documentation](https://learn.chatgpt.com/docs/hooks).

Tested scope and caveats are in [docs/agents.md](docs/agents.md). To run it in a dev container, see [docs/dev-containers.md](docs/dev-containers.md). To use your own policies, see [docs/usage.md](docs/usage.md#custom-policies).

## Included policies

<details>
<summary>All 30 policies</summary>

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
| `DATA-007` | reading credential and secret files (credentials.json, secrets.*, .npmrc, .netrc, kubeconfig, .pem/.key) |
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

</details>

## Limitations

This is a guardrail, not a sandbox. Rules are glob matches on the command string or file path, not a parse of what the shell will actually do.

To make that harder to dodge, Bash commands are checked in several forms: as typed, with whitespace collapsed, and split into sub-commands (`;`, `&&`, `||`, `|`, newlines, `$(...)`, backticks). Leading env assignments and wrappers like `nohup`, `exec` and `env` are stripped, `/bin/rm` and `\rm` are treated as `rm`, and any recursive `rm` (`-r`, `-R`, `-fr`, `--recursive`) is rewritten to `rm -rf`. If several policies match, all of them are reported.

It still cannot see through variable expansion, `eval`, base64-encoded payloads, scripts that do the dangerous thing internally, or `cd` followed by relative paths. Named git remotes are not resolved. Treat the policies as a safety net for mistakes and obvious bad behavior, and use real isolation for anything critical. See [SECURITY.md](SECURITY.md).

## Documentation

- [Using policycheck](docs/usage.md) - custom policies, ignoring a policy, audit log, versions
- [Writing and testing policies](docs/writing-policies.md) - Cedar basics, policy naming, context fields, contributing
- [Dev containers and other sandboxes](docs/dev-containers.md)
- [Codex and other agents](docs/agents.md)
- [SECURITY.md](SECURITY.md) - limits of pattern matching and how to report a bypass

## License

Apache-2.0. See [LICENSE](LICENSE).
