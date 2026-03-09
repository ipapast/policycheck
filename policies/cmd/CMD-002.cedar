@id("CMD-002")
@msg("find -delete on dangerous paths is not allowed (rm -rf bypass)")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "find /* -delete*" ||
    context.command like "find ~ -delete*" ||
    context.command like "find /*-exec rm*" ||
    context.command like "find ~*-exec rm*"
};
