@id("DATA-006")
@msg("searching credential and secret files with Glob/Grep is not allowed")
forbid (
    principal is Agent,
    action in [Action::"Glob", Action::"Grep"],
    resource
) when {
    (context has path && (
        context.path like "*/.ssh*" ||
        context.path like "*/.aws*" ||
        context.path like "*/.config/gcloud*"
    )) ||
    (context has pattern && (
        context.pattern like "*.pem" ||
        context.pattern like "*id_rsa*" ||
        context.pattern like "*id_ed25519*" ||
        context.pattern like "*/.ssh/*" ||
        context.pattern like "*/.aws/*" ||
        context.pattern like "*.env" ||
        context.pattern like "*.env.*" ||
        context.pattern like "*/.env*"
    )) ||
    (context has glob && (
        context.glob like "*.pem" ||
        context.glob like "*.env" ||
        context.glob like "*.env.*" ||
        context.glob like "*id_rsa*"
    ))
};
