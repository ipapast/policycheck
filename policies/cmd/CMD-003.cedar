@id("CMD-003")
@msg("sudo/su/doas privilege escalation is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "sudo *" ||
    context.command like "su *" ||
    context.command like "su" ||
    context.command like "doas *"
};
