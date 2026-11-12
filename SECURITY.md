# Security

policycheck is a guardrail, not a sandbox. Rules are pattern matches on the command string or file path the agent sends, so a determined or creative agent can get around them (extra whitespace, quoting, variable expansion, scripts that do the dangerous thing indirectly, and so on). Use it to catch mistakes and obvious bad behavior, and pair it with real isolation (containers, least-privilege credentials) for anything that matters.

## Reporting a vulnerability

If you find a way to bypass a policy that looks like a bug in the matching logic, or any issue in `policycheck` itself, please open a private security advisory on GitHub (Security tab, "Report a vulnerability"). For plain pattern gaps in a single rule, a regular issue or PR with a failing test case is welcome.
