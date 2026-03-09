@id("TOOL-005")
@msg("writing to CI/CD workflows is not allowed")
forbid (
    principal is Agent,
    action == Action::"Write",
    resource
) when {
    context.file_path like "*/.github/workflows/*"
};
