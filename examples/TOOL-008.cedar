// EXAMPLE: replace "your-github-user" below with your own account, then copy
// this file (and its test file) into policies/ to enable it.
// This catches git push with literal URLs only. It cannot resolve named
// remotes like "origin" to their actual URL. For full coverage, pair this
// with a PreToolUse hook that runs `git remote get-url` to check the
// resolved remote (e.g. in .claude/settings.json).
@id("TOOL-008")
@msg("git push to repositories outside the allowed GitHub account is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "git push *github.com*" ||
    context.command like "git push *gitlab.com*" ||
    context.command like "git push *bitbucket.org*"
} unless {
    context.command like "*github.com/your-github-user*" ||
    context.command like "*github.com:your-github-user*"
};
