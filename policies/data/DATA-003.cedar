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
