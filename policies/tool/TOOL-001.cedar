@id("TOOL-001")
@msg("git force push is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "git push --force*" ||
    context.command like "git push *--force*" ||
    context.command like "git push -f*" ||
    context.command like "git push * -f*" ||
    context.command like "git push +*" ||
    context.command like "git push * +*"
};
