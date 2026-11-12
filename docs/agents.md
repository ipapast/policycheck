# Codex and other agents

## Codex

Codex reports shell calls, including `exec_command`, as `tool_name: "Bash"` with `tool_input.command`. It honors exit code 2 and displays the policy's blocking reason. The Codex configuration in the [README](../README.md#codex) intentionally covers shell calls only.

Tested with Codex CLI **0.167.0 on macOS**:

- A harmless `printf` ran successfully.
- `git push --force origin cedar-audit-test` was blocked by `TOOL-001` in a disposable directory with no Git repository or remote.
- With `POLICYCHECK_AUDIT_LOG` set for the hook, the blocked call was recorded in the built-in JSONL [audit log](usage.md#audit-log). The harmless call was not logged, as designed.

This verifies shell hook integration and block logging, not every policy or the desktop app. Codex's `apply_patch` supplies patch text instead of Claude's `Write`/`Edit` and `file_path`, so the existing file-edit rules do not cover it. The policies also need Codex configuration paths and matching MCP tool names before claiming equivalent coverage across agents. Tests against representative `apply_patch` inputs confirmed that workflow edits currently pass.

## Other agents (untested)

If your agent can run a command before each tool call and treat exit code 2 as "block", you can try piping tool calls to it as JSON. Beyond the tested Codex shell integration above, tool names and input fields need to match Claude Code's (`Bash`, `Read`, `WebFetch`, ...), so other agents will probably need a small adapter:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | policycheck
# exit 2 = blocked, exit 0 = allowed
```
