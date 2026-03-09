---
name: writing-cedar-policies
description: Write and test Cedar security policies for AI agent tool-use guardrails. Use when creating, modifying, or reviewing Cedar policy files in the cedar-policies repository.
---

# Writing Cedar Policies

## Overview

This skill guides writing Cedar security policies that block dangerous tool calls from AI coding agents. Policies are evaluated by a PreToolUse hook before every tool call.

**Announce at start:** "I'm using the writing-cedar-policies skill to implement this policy."

## Architecture

```
Agent tool call
  -> PreToolUse hook fires
  -> policycheck reads JSON from stdin (tool_name + tool_input)
  -> Cedar engine evaluates all policies
  -> exit 0 (allow) or exit 2 (block with ID + message)
```

The input is always:
```json
{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
```

## Cedar Language Rules

- `permit` allows, `forbid` denies - **forbid always wins**
- If nothing permits, the request is denied (default-deny)
- `like` is the only pattern operator: `*` matches any string, no regex
- `like` is **case-sensitive** - match both cases when needed (e.g., `DROP TABLE` and `drop table`)
- All rules are evaluated, not just the first match
- `base.cedar` permits everything by default; individual policies add `forbid` overrides

## Available Context Fields

| Field | Source | Available when |
|---|---|---|
| `context.command` | `tool_input.command` | `action == Action::"Bash"` |
| `context.file_path` | `tool_input.file_path` | `action == Action::"Read"`, `Action::"Write"`, `Action::"Edit"` |

Action is the tool name: `Action::"Bash"`, `Action::"Read"`, `Action::"Write"`, `Action::"Edit"`, `Action::"mcp__*"`, etc.

## Policy Naming Convention

| Prefix | Scope | Examples |
|---|---|---|
| `CMD` | Dangerous commands | rm -rf, sudo, chmod 777, dd, fdisk |
| `DATA` | Secrets and sensitive files | ~/.ssh, .env, credentials |
| `NET` | Network and exfiltration | curl POST, cloud metadata |
| `TOOL` | Tool-specific controls | git push, aws iam, cdk deploy, MCP tools |

Numbers are sequential within each prefix. Check existing policies to find the next number.

## Red-Green Workflow (MANDATORY)

Every policy MUST follow this order. No exceptions.

### Step 1: Write tests first (RED)

Create `POLICY-ID_test.json` next to the policy file:

```json
[
  {
    "name": "blocks dangerous thing",
    "tool_name": "Bash",
    "tool_input": {"command": "dangerous command here"},
    "expect": "block"
  },
  {
    "name": "allows safe thing",
    "tool_name": "Bash",
    "tool_input": {"command": "safe command here"},
    "expect": "allow"
  }
]
```

Rules for test cases:
- Include at least 3-5 block cases covering variations
- Include at least 1-2 allow cases proving safe operations pass
- Test name should describe what is blocked/allowed
- `tool_name` must match the Cedar action (usually `"Bash"`)
- `tool_input` keys must match context fields (`command`, `file_path`)

### Step 2: Verify tests FAIL

```bash
go test ./cmd/policycheck/ -v 2>&1 | grep "POLICY_ID_pattern"
```

All "block" tests MUST fail (showing `expected block, got allow`). All "allow" tests MUST pass. If block tests already pass, you're testing existing behavior - fix your tests.

### Step 3: Write the policy (GREEN)

Create `POLICY-ID.cedar`:

```cedar
@id("POLICY-ID")
@msg("human-readable description of what is blocked")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "pattern*"
};
```

Structure rules:
- `@id` annotation is the policy ID (e.g., `CMD-007`)
- `@msg` annotation is shown to the user when blocked
- Use `||` to combine multiple patterns in one `when` clause
- Use `like` with `*` wildcards for pattern matching
- For case-insensitive matching, add both cases explicitly

### Step 4: Verify ALL tests pass

```bash
go test ./cmd/policycheck/ 2>&1
```

The FULL suite must pass - not just your new tests. New policies can break existing "allow" tests if patterns are too broad.

### Step 5: Commit

One commit per policy with both the `.cedar` and `_test.json` files.

## Common Patterns

### Bash command matching
```cedar
// Exact command start
context.command like "sudo *"

// Command anywhere in pipeline
context.command like "*curl*--data*"

// Multiple variations
context.command like "cdk deploy*" ||
context.command like "npx cdk deploy*"
```

### File path matching (Read/Write/Edit actions)
```cedar
forbid (
    principal is Agent,
    action == Action::"Read",
    resource
) when {
    context.file_path like "*/.ssh/*"
};
```

### MCP tool blocking (by action name, no context needed)
```cedar
forbid (
    principal is Agent,
    action == Action::"mcp__claude_ai_Slack__slack_send_message",
    resource
);
```

## Gotchas

- **`like` is case-sensitive.** `"DROP TABLE"` does not match `"drop table"`. Add both.
- **`*` is greedy.** `"rm *"` matches `"rm -rf /"` but also `"rm file.txt"`. Be specific.
- **Forbid always wins.** If your pattern is too broad, you can't add a `permit` exception. Narrow the `forbid` with `unless` or more specific patterns.
- **New forbids can break existing allow tests.** Always run the full suite.
- **No regex.** Cedar only supports `like` with `*` wildcards. For complex patterns, use multiple `like` clauses joined with `||`.

## Checklist

Before marking complete:

- [ ] Tests written BEFORE policy
- [ ] Block tests confirmed failing (RED)
- [ ] Policy written with @id and @msg annotations
- [ ] All tests pass including full suite (GREEN)
- [ ] Policy uses correct prefix (CMD/DATA/NET/TOOL)
- [ ] Sequential number checked against existing policies
- [ ] Both .cedar and _test.json committed together
