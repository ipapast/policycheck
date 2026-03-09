@id("DATA-005")
@msg("reading system authentication files is not allowed")
forbid (
    principal is Agent,
    action == Action::"Read",
    resource
) when {
    context.file_path like "/etc/passwd" ||
    context.file_path like "/etc/shadow" ||
    context.file_path like "/etc/sudoers" ||
    context.file_path like "/etc/master.passwd"
};
