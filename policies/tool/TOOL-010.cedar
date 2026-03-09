@id("TOOL-010")
@msg("aws iam permission changes are not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "aws iam create-*" ||
    context.command like "aws iam delete-*" ||
    context.command like "aws iam attach-*" ||
    context.command like "aws iam detach-*" ||
    context.command like "aws iam put-*" ||
    context.command like "aws iam update-*" ||
    context.command like "aws iam add-*" ||
    context.command like "aws iam remove-*"
};
