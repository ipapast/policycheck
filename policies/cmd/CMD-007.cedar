@id("CMD-007")
@msg("disk-level commands (dd, mkfs, fdisk, parted) are not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "dd *" ||
    context.command like "mkfs*" ||
    context.command like "fdisk *" ||
    context.command like "parted *"
};
