@id("TOOL-003")
@msg("destructive git operations are not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "git reset --hard*" ||
    context.command like "git checkout ." ||
    context.command like "git clean -f*" ||
    context.command like "git branch -D *" ||
    context.command like "git tag -d *"
};
