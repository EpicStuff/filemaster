# Fix production E2E coverage for Filemaster

Investigate and fix the production-path test gaps exposed by this real install:

```text
FileAccess reports `fileaccess/partial-mount-coverage`.
fanotify logs `fanotify event path unresolved; denying`.
The installed desktop process cannot read GTK/XDG files below
`/home/derek/.home/.config` and `/home/derek/.home/.local`.
libsoup cannot open `hsts-storage.sqlite`.
The desktop reports `Open index.html: file does not exist`.
```

Do not treat these as harmless desktop warnings. They prevent the installed
application from reliably starting and persisting state.

## Goal

Make the release test suite exercise the same boundary as a real installation:
the packaged core, packaged UI archive, installed Tauri binary, an XDG home
inside the watched scope, and real fanotify mount/path behavior. Implement the
smallest production fixes that these tests expose.

## Known blind spots to close

1. `npm run e2e:fileaccess` currently forces the fake fanotify source. Keep it
   as a fast deterministic test, but do not call it sufficient real coverage.

2. The existing real Go fanotify test is opt-in and uses a private temporary
   bind mount. It cannot prove that the host's `/home` mount topology is fully
   marked, nor that a real desktop process can use its own GTK/XDG data.

3. Angular dev-server tests do not validate the installed Tauri artifact or
   the UI ZIP/archive layout. A packaged module missing `index.html` must fail
   before release.

4. Default Allow is not a bypass for early fanotify failures. An unresolved
   descriptor path and a pending/partially marked scope are deliberately
   denied before profile policy runs. Tests must cover that ordering.

## Required work

1. Add a packaging test that builds/stages the production UI artifact and
   verifies every served UI module required by the desktop app contains a
   readable `index.html`. Run the same archive-opening code/path used in
   production where practical; do not merely test an Angular `dist/` folder.

2. Add a production-style desktop smoke test. It must launch the actual built
   Tauri executable against a clean temporary data directory and a controlled
   `HOME`/XDG directory beneath a watched test scope. It must assert:

   - the core reaches a running state;
   - the desktop process loads the packaged UI rather than reporting missing
     `index.html`;
   - GTK/WebKit can read its config and create/open the HSTS SQLite store;
   - window state can be saved;
   - the smoke test fails on `Operation not permitted`, failed desktop config
     loading, unresolved-path denies attributable to the desktop process, or
     partial mount coverage.

   Use a real display stack suitable for CI (for example Xvfb) rather than
   replacing Tauri/WebKit with a unit-test mock.

3. Split capability-dependent coverage cleanly:

   - retain fast fake-source tests;
   - keep hermetic real-fanotify tests for local development;
   - add an explicit privileged release-gate command for the production smoke
     test. If the release gate is selected, unavailable fanotify/display
     capabilities are a failure, not a silent skip. Local opt-in tests may
     still skip with a precise reason.

4. Improve fanotify diagnostics and tests so partial coverage reports the
   configured scope, canonical scope, missing mount IDs, and the relevant
   mountinfo entries. Ensure the E2E failure output includes that data.

5. Reproduce the actual user-home shape from the report (`HOME` resolving to
   `/home/derek/.home`) in a test. Determine whether that is a launcher bug or
   intentional XDG configuration. Preserve standard XDG behavior if it is
   intentional; otherwise correct the launcher and add a regression test.

6. Fix any production bug found by these tests. Do not weaken fail-closed
   behavior for arbitrary unresolved descriptors merely to make the test
   pass. If Filemaster must permit its own UI storage, make that scope and its
   security rationale explicit and test it.

## Verification and handoff

1. Run focused Go/Rust/Angular tests for changed components.
2. Run the existing fake E2E test and the new production-style smoke test.
3. Run the full relevant build/package command, then validate the staged
   artifact rather than the source tree.
4. For any UI change: start the actual dev app, exercise the changed screen,
   capture and inspect a screenshot, and run the relevant E2E test before
   commit.
5. Report exact commands, whether each used real fanotify or a fake source,
   and any capability prerequisite. Do not claim production coverage from a
   skipped test.

## Evidence needed from the affected machine

Collect the File Access diagnostics payload while the failure is active,
including configured/canonical watch paths, missing mount IDs, and mountinfo.
Also retain the complete install tree or package artifact that produced
`Open index.html: file does not exist`; the current `/tmp/filemaster/install`
directory is empty, so it cannot be inspected after the fact.
