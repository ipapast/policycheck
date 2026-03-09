@id("TOOL-007")
@msg("sending Slack messages via MCP is not allowed")
forbid (
    principal is Agent,
    action == Action::"mcp__claude_ai_Slack__slack_send_message",
    resource
);

@id("TOOL-007b")
@msg("sending Slack message drafts via MCP is not allowed")
forbid (
    principal is Agent,
    action == Action::"mcp__claude_ai_Slack__slack_send_message_draft",
    resource
);

@id("TOOL-007c")
@msg("scheduling Slack messages via MCP is not allowed")
forbid (
    principal is Agent,
    action == Action::"mcp__claude_ai_Slack__slack_schedule_message",
    resource
);

@id("TOOL-007d")
@msg("creating Slack canvases via MCP is not allowed")
forbid (
    principal is Agent,
    action == Action::"mcp__claude_ai_Slack__slack_create_canvas",
    resource
);

@id("TOOL-007e")
@msg("posting Slack messages via the Slack MCP server is not allowed")
forbid (
    principal is Agent,
    action == Action::"mcp__slack__slack_post_message",
    resource
);
