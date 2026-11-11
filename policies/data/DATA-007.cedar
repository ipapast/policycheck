@id("DATA-007")
@msg("reading credential and secret files (credentials.json, secrets.*, .npmrc, .netrc, kubeconfig, .pem/.key, ...) is not allowed")
forbid (
    principal is Agent,
    action == Action::"Read",
    resource
) when {
    context.file_path like "*/credentials.json" ||
    context.file_path like "*/credentials.yaml" ||
    context.file_path like "*/credentials.yml" ||
    context.file_path like "*/secrets.json" ||
    context.file_path like "*/secrets.yaml" ||
    context.file_path like "*/secrets.yml" ||
    context.file_path like "*/secrets.toml" ||
    context.file_path like "*/.npmrc" ||
    context.file_path like "*/.netrc" ||
    context.file_path like "*/.pgpass" ||
    context.file_path like "*/.git-credentials" ||
    context.file_path like "*/.pypirc" ||
    context.file_path like "*/.docker/config.json" ||
    context.file_path like "*/.kube/config" ||
    context.file_path like "*.pem" ||
    context.file_path like "*.key"
};

@id("DATA-007b")
@msg("accessing credential and secret files via shell commands is not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "*credentials.json*" ||
    context.command like "*credentials.yaml*" ||
    context.command like "*credentials.yml*" ||
    context.command like "*secrets.json*" ||
    context.command like "*secrets.yaml*" ||
    context.command like "*secrets.yml*" ||
    context.command like "*secrets.toml*" ||
    context.command like "*.npmrc*" ||
    context.command like "*.netrc*" ||
    context.command like "*.pgpass*" ||
    context.command like "*.git-credentials*" ||
    context.command like "*.pypirc*" ||
    context.command like "*.docker/config.json*" ||
    context.command like "*.kube/config*" ||
    context.command like "*.pem" ||
    context.command like "*.pem *" ||
    context.command like "*.key" ||
    context.command like "*.key *"
};
