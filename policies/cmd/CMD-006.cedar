@id("CMD-006")
@msg("kill -9 is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "kill -9 *"
};
