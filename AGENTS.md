Go read ./CLAUDE.md

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
