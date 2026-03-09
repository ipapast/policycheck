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
