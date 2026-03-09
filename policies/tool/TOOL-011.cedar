@id("TOOL-011")
@msg("aws s3 mass deletion is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "aws s3 rm *--recursive*" ||
    context.command like "aws s3 rb *"
};
