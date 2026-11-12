# Dev containers and other sandboxes

Because the binary is static and self-contained, it works inside a container with no Go toolchain and no copy of this repo. Claude Code and its hooks run in the same container, so the policies apply there too.

Build the binary in a throwaway stage and copy it in:

```dockerfile
FROM golang:1.24 AS policycheck
RUN CGO_ENABLED=0 go install github.com/ipapast/policycheck/cmd/policycheck@latest

FROM mcr.microsoft.com/devcontainers/base:ubuntu
COPY --from=policycheck /go/bin/policycheck /usr/local/bin/policycheck
```

Then use `"command": "policycheck"` in the project's `.claude/settings.json`, as in the [README quick start](../README.md#claude-code). A few things to know:

- **Settings live in your repo.** The hook config is only as trustworthy as the files the agent can edit. `TOOL-006` blocks edits to agent settings, but keep the binary somewhere the agent can't write (`/usr/local/bin` owned by root, as in the Dockerfile above).
- **Ignores and the audit log** use the container's filesystem. `.cedar-ignores.json` is read from the working directory. Point `POLICYCHECK_AUDIT_LOG` at a mounted volume if you want the log to outlive the container.
- **Cross-compiling** works too, for example `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/policycheck`, if you build on a Mac and run in a Linux container.
- **It is not isolation.** The container is your boundary. These policies are a check inside it.
