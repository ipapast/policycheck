// Allow all non-Bash tools by default
permit (
    principal is Agent,
    action,
    resource
) unless {
    action == Action::"Bash"
};

// Allow Bash commands by default (forbid rules below override)
permit (
    principal is Agent,
    action == Action::"Bash",
    resource
);
