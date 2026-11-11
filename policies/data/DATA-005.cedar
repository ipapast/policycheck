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

@id("DATA-005b")
@msg("accessing system authentication files via shell commands is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "*/etc/passwd*" ||
    context.command like "*/etc/shadow*" ||
    context.command like "*/etc/sudoers*" ||
    context.command like "*/etc/master.passwd*"
};
