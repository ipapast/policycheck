@id("TOOL-006")
@msg("editing agent settings and security files is not allowed")
forbid (
    principal is Agent,
    action == Action::"Edit",
    resource
) when {
    context.file_path like "*/.claude/settings.json" ||
    context.file_path like "*/.claude/settings.local.json" ||
    context.file_path like "*/.claude/SECURITY.md"
};

@id("TOOL-006b")
@msg("writing agent settings and security files is not allowed")
forbid (
    principal is Agent,
    action == Action::"Write",
    resource
) when {
    context.file_path like "*/.claude/settings.json" ||
    context.file_path like "*/.claude/settings.local.json" ||
    context.file_path like "*/.claude/SECURITY.md"
};
