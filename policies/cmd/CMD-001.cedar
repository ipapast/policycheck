@id("CMD-001")
@msg("rm -r/-rf on dangerous paths (/, ~, *) is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "rm -rf /*" ||
    context.command like "rm -r /*" ||
    context.command like "rm -rf ~*" ||
    context.command like "rm -r ~*" ||
    context.command like "rm -rf \*" ||
    context.command like "rm -r \*"
};
