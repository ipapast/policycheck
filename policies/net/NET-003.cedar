// Cloud VMs expose a metadata endpoint (169.254.169.254) that returns
// IAM credentials, session tokens, and instance identity. An agent running
// inside EC2/GCE/Azure could hit this to obtain AWS/GCP/Azure credentials
// without anyone explicitly providing them.
@id("NET-003")
@msg("accessing cloud metadata endpoints is not allowed (SSRF risk)")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "*169.254.169.254*" ||
    context.command like "*metadata.google.internal*" ||
    context.command like "*metadata.azure.com*"
};
