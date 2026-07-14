# Filemaster open issues

## Test coverage gaps

### ISSUE-1: No Angular unit test for getProfileStats app_name mapping

`Filequery.getProfileStats` (in `projects/safing/portmaster-api/src/lib/
filequery.service.ts`) now selects `app_name` and uses it as the display
Name (falling back to the profile ID). There is no karma spec covering this.
A spec should mock the batch HTTP response and assert:
- `stats.Name === "Sleep"` when a row has `app_name = "Sleep"`
- `stats.Name === stats.ID` when `app_name` is empty

File: `projects/safing/portmaster-api/src/lib/filequery.service.spec.ts` (create)

### ISSUE-2: No e2e assertion for clicking a sidebar app into its app-view

`file-access.spec.ts` verifies the prompt → verdict → monitor flow and that
the monitor shows the resolved app names (sleep/tail). It does not click a
sidebar entry and assert the real profile app-view renders (header + File
Events tab). This was verified manually (screenshot) but not automated.
Add steps: click the app row, expect URL `/app/local/<id>`, expect the app
name heading and a File Events row for the injected path.

## Minor / pre-existing (not introduced by the profile-resolution work)

### ISSUE-3: dead const `unknownExe` in prompt.go

`const unknownExe = ""` (prompt.go:23) is declared but unused. Harmless;
remove when next touching that file.

### ISSUE-4: unchecked scanner.Err() in socket_source.go

The `bufio.Scanner` loop in `socketSource.Run` doesn't check `scanner.Err()`
after the loop. Test/dev-only source, so low impact, but worth a final
error check for cleanliness.
