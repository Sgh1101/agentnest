/**
 * Where the Codex hooks file lives. The hooks.json draft itself and the doctor command line are built by the daemon
 * (they carry the absolute path of the installed hook program, which is not on PATH, and the current approval TTL),
 * so this front end holds no program name or timeout of its own.
 * UNVERIFIED (Phase 0 C6): the top-level structure, matcher field names and the trust procedure are not confirmed yet.
 */
export const CODEX_HOOKS_PATH = "%USERPROFILE%\\.codex\\hooks.json";
