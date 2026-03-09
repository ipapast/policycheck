@id("CMD-005")
@msg("privileged Docker containers are not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "docker run *--privileged*" ||
    context.command like "docker run *-v /*"
};
