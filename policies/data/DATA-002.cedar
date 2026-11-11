@id("DATA-002")
@msg("reading credential and cloud config files is not allowed")
forbid (
    principal is Agent,
    action == Action::"Read",
    resource
) when {
    context.file_path like "*/.ssh/*" ||
    context.file_path like "*/.aws/*" ||
    context.file_path like "*/.config/gcloud/*"
};

@id("DATA-002b")
@msg("accessing credential and cloud config files via shell commands is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "*/.ssh*" ||
    context.command like "*.ssh/*" ||
    context.command like "*/.aws*" ||
    context.command like "*.aws/*" ||
    context.command like "*/.config/gcloud*"
};
