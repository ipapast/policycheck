# Codex and other agents

## Codex

Codex reports shell calls, including `exec_command`, as `tool_name: "Bash"` with `tool_input.command`. It honors exit code 2 and displays the policy's blocking reason. The Codex configuration in the [README](../README.md#codex) covers shell calls and native `apply_patch` edits. If you previously used `"matcher": "Bash"`, change it to `"matcher": "^(Bash|apply_patch)$"` and review the updated hook in Codex.

Tested with Codex CLI **0.167.0 on macOS**:

- A harmless `printf` ran successfully.
- Representative commands for all 24 built-in shell-policy families were blocked by their expected rules. The test harness prevented execution even if a rule unexpectedly allowed a command; that fallback was never needed.
- Normal `apply_patch` adds, updates, deletes and moves succeeded.
- Workflow creation, updates, deletion and moves in either direction were blocked. A mixed patch containing a normal file and a Codex hook-settings file was rejected in full; neither file was created. Protected existing files remained unchanged.
- Scoped ignores allowed only the intended patch targets. Expired ignores, similar directory prefixes, symlink targets outside the scope, and mixed allowed/blocked patches remained blocked.
- Seven MCP calls against local test doubles verified both permitted reads and all five prohibited Slack operations. Only the two reads reached the mock servers; no real Slack connection was used.
- With `POLICYCHECK_AUDIT_LOG` set for the hook, blocked shell, patch and MCP calls were recorded in the built-in JSONL [audit log](usage.md#audit-log). Ignored violations were logged as allowed, and patch violations included their affected paths. Harmless calls were not logged, as designed.

### File edits

Codex sends native `apply_patch` text in `tool_input.command`. The adapter extracts every Add, Update and Delete path, plus both the source and destination of a Move. It checks each target against **both `Write` and `Edit` policies**. Any non-ignored violation blocks the entire patch before Codex changes files, including any otherwise allowed files in the same patch.

Relative paths are resolved against the hook's `cwd` (or the hook process directory when omitted). The adapter checks normalized absolute paths and existing symlink targets. Unsupported patch syntax or path-resolution errors block the call. Patch content is not treated as a file target.

`TOOL-006` also protects `.codex/config.toml`, `.codex/hooks.json`, `.codex/requirements.toml`, and files under `.codex/hooks/` and `.codex/rules/`. Scoped ignores apply separately to each affected path. Audit entries retain `tool: "apply_patch"` and the patch command, and each file-policy violation includes its resolved `file_path`.

The CLI regression tests cover adds, updates, deletes, moves in both directions, mixed patches, relative paths, symlinks, malformed input, custom Write/Edit policies, scoped ignores and audit records.

### Terminal verification

Verified on 2026-11-12:

| Check | Result |
|---|---|
| `go vet ./...` and `go test -race ./...` | Passed on macOS arm64 and Linux arm64 (Docker) |
| All 249 built-in policy fixtures through the compiled CLI | Passed with both embedded and disk policies: 498 cases |
| Named built-in rules exercised by blocking fixtures | All 41 |
| Write/Edit fixtures replayed as five patch operations | 90 cases passed |
| Custom example-policy fixtures through the CLI | All 6 passed |
| Ignore creation, listing, replacement, expiry and removal | Passed, including malformed ignore-file handling |
| Concurrent audit appends | 32 blocked calls produced 32 valid JSONL records |
| Generated mixed-patch corpus | 1,000 cases passed: 500 allowed and 500 blocked |

Run `go test ./...` to repeat the repository's CLI regression tests. The live Codex checks and generated corpus above were separate terminal verification runs.

### Coverage limits

The README matcher covers `Bash` and `apply_patch`. To enforce MCP policies too, include MCP names in the matcher (for example `"^(Bash|apply_patch|mcp__.*)$"`) or use an empty matcher for all supported local tools. The MCP tests used an empty matcher. Rules must still match the actual server/tool names; testing a local mock does not verify a real provider's integration.

Claude-specific Read, Glob, Grep and WebFetch inputs were verified through policy fixtures, not as native Codex tools. Arbitrary file writes through shell scripts remain outside the patch adapter. Hosted tools and the desktop UI were not tested. Passing these checks establishes the tested cases, not exhaustive protection against every command spelling or bypass.

## Other agents (untested)

If your agent can run a command before each tool call and treat exit code 2 as "block", you can try piping tool calls to it as JSON. Beyond the tested Codex integration above, tool names and input fields need to match Claude Code's (`Bash`, `Read`, `WebFetch`, ...), so other agents will probably need a small adapter:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | policycheck
# exit 2 = blocked, exit 0 = allowed
```
