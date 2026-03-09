@id("TOOL-002")
@msg("modifying git remotes is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "git remote add *" ||
    context.command like "git remote set-url *"
};
