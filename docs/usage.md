# Using policycheck

Day-to-day usage: custom policies, ignores, the audit log and versions.

## Custom policies

Pass a directory to use your own policies instead of the built-in ones:

```bash
git clone https://github.com/ipapast/policycheck.git
policycheck /path/to/policycheck/policies
```

A directory replaces the built-in set entirely (it is not merged), so start from a copy of `policies/` and edit it. Policies are embedded from `policies/` at build time, so changes to the repo only reach the built-in set after you rebuild or reinstall.

## Ignoring policies

You can temporarily suppress a policy per project. Default expiry is 1 week.

```bash
# Ignore a policy
policycheck ignore CMD-001 --reason "cleanup script needs rm -rf"

# Ignore only for a specific path
policycheck ignore CMD-001 --reason "cleanup script" --path "/tmp"

# Ignore with custom expiry
policycheck ignore CMD-001 --reason "migration" --expires 2026-04-01

# List active ignores
policycheck list-ignores

# Remove an ignore
policycheck unignore CMD-001
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
