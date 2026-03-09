@id("TOOL-013")
@msg("destructive psql commands (DROP, TRUNCATE) are not allowed")
forbid (
    principal is Agent,
    action == Action::"Bash",
    resource
) when {
    context.command like "*psql*DROP DATABASE*" ||
    context.command like "*psql*drop database*" ||
    context.command like "*psql*DROP TABLE*" ||
    context.command like "*psql*drop table*" ||
    context.command like "*psql*DROP SCHEMA*" ||
    context.command like "*psql*drop schema*" ||
    context.command like "*psql*TRUNCATE*" ||
    context.command like "*psql*truncate*"
};
