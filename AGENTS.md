Go read ./CLAUDE.md

## Language-server readiness

Before code navigation, identify the languages in the files being changed and
ensure Serena has suitable language-server support. For a nested project,
activate its most-specific `.serena/project.yml` (for example,
`desktop/angular` for the Angular UI), not just the repository root. Install
any missing language server or runtime that is needed or materially useful,
following the shared package-installation guide, configure it in Serena, and
verify it with a semantic request before proceeding. Do not leave an available,
relevant server unconfigured merely because a text-search fallback works.

After completing a user-requested implementation, commit the scoped changes and
push the current branch unless the user explicitly asks not to push.

## UI verification gate

For every UI change, before commit or push:

1. Start the actual dev app and wait for the final `Compiled successfully` line.
   Do not infer success from a command exiting, detaching, or lack of output.
2. Exercise the changed screen in a browser.
3. Capture and inspect a screenshot of the changed screen. State in the final
   response that the screenshot was inspected.
4. Run the relevant E2E test. If it cannot run, report it as unverified; do not
   describe it as passing.
5. Only commit/push after all applicable checks pass. If a check is blocked,
   stop and ask the user rather than pushing.

Every UI handoff must include:

- Dev compile: exact final result
- Browser path tested
- Screenshot inspected
- E2E command/result

No screenshot or final successful compiler output means the UI is unverified.
