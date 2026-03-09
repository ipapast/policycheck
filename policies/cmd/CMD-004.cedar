@id("CMD-004")
@msg("chmod 777 and recursive chown are not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "chmod -R 777*" ||
    context.command like "chmod 777 *" ||
    context.command like "chown -R*"
};
