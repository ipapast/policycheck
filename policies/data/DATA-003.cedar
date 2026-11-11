@id("DATA-003")
@msg("reading .env files is not allowed")
forbid (
    principal is Agent,
    action == Action::"Read",
    resource
) when {
    context.file_path like "*/.env" ||
    context.file_path like "*/.env.*"
};

@id("DATA-003b")
@msg("accessing .env files via shell commands is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "* .env" ||
    context.command like "* .env *" ||
    context.command like "* .env.*" ||
    context.command like "*/.env" ||
    context.command like "*/.env *" ||
    context.command like "*/.env.*"
};
