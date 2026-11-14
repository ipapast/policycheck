// An "ask" version of TOOL-009. Instead of blocking a push to main or master,
// Claude Code shows a permission prompt so you can approve it. In other agents
// (Codex, for example) it still blocks.
//
// To use it, copy policies/ to your own directory, delete
// policies/tool/TOOL-009.cedar and put this file in its place. If both are
// loaded, TOOL-009 still blocks the push.
@id("TOOL-009a")
@msg("pushing directly to main or master needs your approval")
@decision("ask")
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
