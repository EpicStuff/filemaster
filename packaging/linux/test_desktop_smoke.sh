#!/usr/bin/env bash
# Production-style desktop smoke test.
#
# Launches the built Tauri executable against a clean data directory and an
# XDG home that lives *inside* a watched fanotify scope, which is the shape a
# real installation has when the default "+ /home" watch path covers the user
# running the desktop. It asserts the desktop actually starts, loads the
# packaged UI archive, and can read and write its own storage.
#
# Set FM_RELEASE_GATE=1 to make missing fanotify or display capabilities a
# failure instead of a skip.
set -uo pipefail

repo_root=$1
core_bin=$2
desktop_bin=$3
ui_zip=$4
assets_zip=$5

release_gate=${FM_RELEASE_GATE:-0}

unavailable() {
	if [ "$release_gate" = 1 ]; then
		echo "release gate: required capability unavailable: $1" >&2
		exit 1
	fi
	echo "skipping desktop smoke test: $1" >&2
	exit 0
}

fail() {
	echo "desktop smoke test FAILED: $1" >&2
	# The API exposes the complete, structured scope-coverage report. Print it
	# before preserving logs so a release-gate failure directly identifies the
	# configured/canonical scopes, unmarked mount IDs, and mountinfo rows.
	if [ -n "${core_pid:-}" ] && [ -n "${port:-}" ] && kill -0 "$core_pid" 2>/dev/null; then
		echo '--- file access diagnostics ---' >&2
		curl -sf "http://127.0.0.1:$port/api/v1/fileaccess/diagnostics" >&2 || \
			echo 'file access diagnostics unavailable' >&2
	fi
	# Keep the full logs: the interesting evidence (scope activation, coverage
	# diagnostics, self-storage registration) is emitted at startup, far outside
	# any tail window.
	keep=${FM_SMOKE_LOG_DIR:-/tmp/filemaster-smoke-logs}
	mkdir -p "$keep"
	[ -n "${core_log:-}" ] && [ -f "$core_log" ] && cp "$core_log" "$keep/core.log"
	[ -n "${ui_log:-}" ] && [ -f "$ui_log" ] && cp "$ui_log" "$keep/ui.log"
	echo "full logs preserved in $keep" >&2
	[ -n "${core_log:-}" ] && [ -f "$core_log" ] && { echo '--- core log (tail) ---' >&2; tail -40 "$core_log" >&2; }
	[ -n "${ui_log:-}" ] && [ -f "$ui_log" ] && { echo '--- desktop log (tail) ---' >&2; tail -40 "$ui_log" >&2; }
	exit 1
}

for tool in xvfb-run unshare mount curl; do
	command -v "$tool" >/dev/null || unavailable "$tool is not installed"
done
[ "$(id -u)" = 0 ] || unavailable 'fanotify mount marks need CAP_SYS_ADMIN in the initial user namespace'
[ -x "$core_bin" ] || fail "core binary not built: $core_bin"
[ -x "$desktop_bin" ] || fail "desktop binary not built: $desktop_bin"
[ -f "$ui_zip" ] || fail "UI archive not built: $ui_zip"

# The fanotify group, its mount mark and the watch scope all stay inside a
# private mount namespace so a failing run cannot leave the host marked.
if [ "${FM_DESKTOP_SMOKE_CONFINED:-0}" != 1 ]; then
	exec env FM_DESKTOP_SMOKE_CONFINED=1 unshare --mount --propagation private \
		"$0" "$repo_root" "$core_bin" "$desktop_bin" "$ui_zip" "$assets_zip"
fi

work=$(mktemp -d)
core_pid=''
cleanup() {
	# The core must exit before the scope is unmounted and removed: while its
	# fanotify marks are live, cleanup itself is subject to them.
	if [ -n "$core_pid" ]; then
		kill "$core_pid" 2>/dev/null
		for _ in $(seq 1 50); do
			kill -0 "$core_pid" 2>/dev/null || break
			sleep 0.2
		done
		kill -9 "$core_pid" 2>/dev/null
		wait "$core_pid" 2>/dev/null
	fi
	umount -l /home/fmsmoke 2>/dev/null
	rmdir /home/fmsmoke 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work"/{data,bin}
# The watch scope is a real /home path so it matches the seeded rules the way an
# installed system does. It only exists inside this private mount namespace.
watched=/home/fmsmoke
mkdir -p "$watched"
mount -t tmpfs tmpfs "$watched" 2>/dev/null || unavailable 'cannot mount a private watch scope'

home="$watched"
mkdir -p "$home/.config/filemaster" "$home/.local/share"
# Seed a valid desktop config. config::load logs the same error for "missing"
# and "unreadable" (desktop/tauri/src-tauri/src/config.rs), so without an
# existing file the error says nothing about whether reads were denied.
printf '%s\n' '{"theme":"System"}' >"$home/.config/filemaster/config.json"
# Install the same layout `make install` produces: both binaries live in the
# root-owned bin dir, which is what identifies them as Filemaster's own.
cp "$core_bin" "$work/bin/filemaster-core"
cp "$desktop_bin" "$work/bin/filemaster"
cp "$ui_zip" "$work/bin/filemaster.zip"
[ -f "$assets_zip" ] && cp "$assets_zip" "$work/bin/assets.zip"

port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
core_log="$work/core.log"
ui_log="$work/ui.log"

# "permit" is the shipped default (service/profile/config.go); prompt mode is
# what the product is for, so the smoke test can exercise either.
default_action=${FM_SMOKE_DEFAULT_ACTION:-permit}

# Watch paths come from config; the daemon does not read FM_WATCH_PATHS.
cat >"$work/data/config.json" <<EOF
{
  "core": { "devMode": true },
  "fileaccess": { "watchPaths": ["+ $watched"], "interceptReads": true },
  "filter": { "defaultAction": "$default_action" }
}
EOF

"$work/bin/filemaster-core" --devmode --log debug \
	--api-address "127.0.0.1:$port" \
	--data-dir "$work/data" --bin-dir "$work/bin" >"$core_log" 2>&1 &
core_pid=$!

for _ in $(seq 1 90); do
	curl -sf -o /dev/null "http://127.0.0.1:$port/api/v1/ping" && break
	kill -0 "$core_pid" 2>/dev/null || fail 'core exited before reaching a running state'
	sleep 1
done
curl -sf -o /dev/null "http://127.0.0.1:$port/api/v1/ping" || fail 'core never reached a running state'

grep -q "fanotify source ready" "$core_log" || {
	grep -qi 'fanotify_init' "$core_log" && unavailable 'fanotify_init is not permitted on this host'
	fail 'fanotify source never became ready'
}
# Guard against the scope silently falling back to the configured default.
grep -q "paths=\"\[+ $watched\]\"" "$core_log" || fail "core did not adopt the test watch scope; got: $(grep -o 'paths="\[[^]]*\]"' "$core_log" | head -1)"

HOME="$home" \
XDG_CONFIG_HOME="$home/.config" \
XDG_DATA_HOME="$home/.local/share" \
	timeout 100 xvfb-run -a "$work/bin/filemaster" \
	--api-address "127.0.0.1:$port" --data "$work/bin" >"$ui_log" 2>&1
desktop_status=$?
# A GUI that is still running when the timeout fires is the healthy outcome.
[ "$desktop_status" = 124 ] || [ "$desktop_status" = 0 ] || fail "desktop exited with status $desktop_status"

grep -qi 'cannot open display\|Xvfb failed' "$ui_log" && unavailable 'no usable X display for WebKit'

grep -q 'main window page loaded' "$ui_log" || fail 'desktop never finished loading a page'
grep -q 'ui/modules/filemaster/' "$ui_log" || fail 'desktop did not load the packaged UI module'
grep -qi 'file does not exist' "$ui_log" && fail 'desktop could not open index.html from the packaged UI archive'
grep -qi 'operation not permitted' "$ui_log" && fail 'desktop was denied access to its own storage'
grep -qi 'failed to load config file' "$ui_log" && fail 'desktop could not read its seeded config file'

find "$home" -name 'hsts-storage.sqlite' | grep -q . || fail 'WebKit could not create its HSTS SQLite store'
find "$home" -name '.window-state.json' | grep -q . || fail 'window state was not saved'

grep -qi 'partial-mount-coverage\|mount coverage partial' "$core_log" && fail 'fanotify reported partial mount coverage'
grep -qi 'path unresolved' "$core_log" && fail 'fanotify denied an event with an unresolved path'
# The mount-namespace-isolated diagnostic is expected here and is not asserted:
# this harness deliberately confines the core to a private mount namespace, and
# the desktop it watches runs inside that same namespace.

# Note: the "fanotify event ... verdict=pending" log line is emitted before the
# async decision pipeline resolves the event, so it appears for every delivered
# event and is not evidence of a deny. The functional assertions above (page
# loaded, HSTS store created, window state saved, config readable) are what
# actually prove the desktop was not blocked on its own storage.

echo 'desktop smoke test passed (real fanotify, real Xvfb display, packaged UI archive)'
