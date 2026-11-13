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
    context.command like "git tag -d *" ||
    context.command like "git checkout -- *" ||
    context.command like "git restore ." ||
    context.command like "git restore -- *" ||
    context.command like "git restore --worktree*" ||
    context.command like "git restore -W*" ||
    context.command like "git stash drop*" ||
    context.command like "git stash clear*"
};
