@id("NET-001")
@msg("piping downloads to shell execution is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "curl *|*sh" ||
    context.command like "curl *|*bash" ||
    context.command like "wget *|*sh" ||
    context.command like "wget *|*bash" ||
    context.command like "*sh <(curl *" ||
    context.command like "*sh <(wget *" ||
    context.command like "source <(curl *" ||
    context.command like "source <(wget *" ||
    context.command like ". <(curl *" ||
    context.command like ". <(wget *"
};
