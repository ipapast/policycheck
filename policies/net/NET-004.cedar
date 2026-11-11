@id("NET-004")
@msg("fetching localhost, private network and internal URLs is not allowed")
forbid (
    principal is Agent,
    action == Action::"WebFetch",
    resource
) when {
    context has url &&
    (
        context.url like "*://localhost*" ||
        context.url like "*@localhost*" ||
        context.url like "*://127.*" ||
        context.url like "*@127.*" ||
        context.url like "*://0.0.0.0*" ||
        context.url like "*@0.0.0.0*" ||
        context.url like "*://[::1]*" ||
        context.url like "*@[::1]*" ||
        context.url like "*://169.254.*" ||
        context.url like "*@169.254.*" ||
        context.url like "*://10.*" ||
        context.url like "*@10.*" ||
        context.url like "*://192.168.*" ||
        context.url like "*@192.168.*" ||
        context.url like "*://172.16.*" ||
        context.url like "*@172.16.*" ||
        context.url like "*://172.17.*" ||
        context.url like "*@172.17.*" ||
        context.url like "*://172.18.*" ||
        context.url like "*@172.18.*" ||
        context.url like "*://172.19.*" ||
        context.url like "*@172.19.*" ||
        context.url like "*://172.20.*" ||
        context.url like "*@172.20.*" ||
        context.url like "*://172.21.*" ||
        context.url like "*@172.21.*" ||
        context.url like "*://172.22.*" ||
        context.url like "*@172.22.*" ||
        context.url like "*://172.23.*" ||
        context.url like "*@172.23.*" ||
        context.url like "*://172.24.*" ||
        context.url like "*@172.24.*" ||
        context.url like "*://172.25.*" ||
        context.url like "*@172.25.*" ||
        context.url like "*://172.26.*" ||
        context.url like "*@172.26.*" ||
        context.url like "*://172.27.*" ||
        context.url like "*@172.27.*" ||
        context.url like "*://172.28.*" ||
        context.url like "*@172.28.*" ||
        context.url like "*://172.29.*" ||
        context.url like "*@172.29.*" ||
        context.url like "*://172.30.*" ||
        context.url like "*@172.30.*" ||
        context.url like "*://172.31.*" ||
        context.url like "*@172.31.*" ||
        context.url like "*://*.internal*" ||
        context.url like "*://*.local*" ||
        context.url like "*@*.internal*"
    )
};
