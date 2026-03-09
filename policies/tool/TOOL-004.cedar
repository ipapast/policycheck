@id("TOOL-004")
@msg("package publishing is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "npm publish*" ||
    context.command like "yarn publish*" ||
    context.command like "npx publish*"
};
