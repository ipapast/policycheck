@id("NET-002")
@msg("data exfiltration via curl/wget POST is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "curl *--data*" ||
    context.command like "curl *-X POST*" ||
    context.command like "curl *-X PUT*" ||
    context.command like "curl *-d *" ||
    context.command like "wget *--post-data*"
};
