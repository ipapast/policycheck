@id("TOOL-009")
@msg("pushing directly to main or master is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "git push * main" ||
    context.command like "git push * main *" ||
    context.command like "git push * master" ||
    context.command like "git push * master *"
};
