@id("DATA-004")
@msg("writing to shell config and dotfiles is not allowed")
forbid (
    principal is Agent,
    action == Action::"Write",
    resource
) when {
    context.file_path like "*/.zshrc" ||
    context.file_path like "*/.bashrc" ||
    context.file_path like "*/.bash_profile" ||
    context.file_path like "*/.zprofile" ||
    context.file_path like "*/.gitconfig"
};

@id("DATA-004b")
@msg("reading shell config and dotfiles is not allowed")
forbid (
    principal is Agent,
    action == Action::"Read",
    resource
) when {
    context.file_path like "*/.zshrc" ||
    context.file_path like "*/.bashrc" ||
    context.file_path like "*/.bash_profile" ||
    context.file_path like "*/.zprofile" ||
    context.file_path like "*/.gitconfig"
};

@id("DATA-004c")
@msg("editing shell config and dotfiles is not allowed")
forbid (
    principal is Agent,
    action == Action::"Edit",
    resource
) when {
    context.file_path like "*/.zshrc" ||
    context.file_path like "*/.bashrc" ||
    context.file_path like "*/.bash_profile" ||
    context.file_path like "*/.zprofile" ||
    context.file_path like "*/.gitconfig"
};
