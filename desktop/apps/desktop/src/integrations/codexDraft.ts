/**
 * Draft ~/.codex/hooks.json from docs/integrations/codex.md 5.1.
 * UNVERIFIED (Phase 0 C6): the top-level structure, matcher field names and the trust procedure are
 * not confirmed yet, so the UI labels this as a draft and the installer stays disabled.
 */
const EVENTS: ReadonlyArray<readonly [string, number]> = [
  ["SessionStart", 5],
  ["UserPromptSubmit", 5],
  ["PreToolUse", 5],
  ["PermissionRequest", 150],
  ["PostToolUse", 5],
  ["Stop", 5],
  ["Interrupt", 2],
  ["SessionEnd", 3],
];

export function codexHooksDraft(): string {
  const hooks: Record<string, unknown> = {};
  for (const [name, timeout] of EVENTS) {
    hooks[name] = [
      {
        matcher: "",
        hooks: [{ type: "command", command: "agentnest-hook codex", commandWindows: "agentnest-hook.exe codex", timeout }],
      },
    ];
  }
  return JSON.stringify({ hooks }, null, 2);
}

export const CODEX_HOOKS_PATH = "%USERPROFILE%\\.codex\\hooks.json";
