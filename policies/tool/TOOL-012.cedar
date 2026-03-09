@id("TOOL-012")
@msg("cdk deploy/destroy is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "cdk deploy*" ||
    context.command like "cdk destroy*" ||
    context.command like "npx cdk deploy*" ||
    context.command like "npx cdk destroy*"
};
