@id("DATA-001")
@msg("environment variable dumping is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "env" ||
    context.command like "env *" ||
    context.command like "printenv" ||
    context.command like "printenv *" ||
    context.command like "export -p" ||
    context.command like "export -p *"
};
