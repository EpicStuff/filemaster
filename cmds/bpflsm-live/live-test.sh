#!/bin/bash
# Live daemon check for the M2 fix-up with a block default: the real daemon
# denies in-scope structural ops, allows out-of-scope, survives SIGKILL, and
# reports coverage on restart and off.
set -u
CORE=${CORE:-./filemaster-core}
D=/tmp/fmdata
API=http://127.0.0.1:818/api/v1/fileaccess/diagnostics

start() {
	nohup "$CORE" --data-dir "$D" --log warning --devmode >>/tmp/fm.log 2>&1 &
	echo $! >/tmp/fm.pid
	for _ in $(seq 90); do curl -sf "$API" >/dev/null && return 0; sleep 1; done
	echo "daemon did not come up"; tail -20 /tmp/fm.log; return 1
}
diag() {
	curl -s "$API" | jq -c '{mode:.Structural.Mode,state:.Structural.State,gen:(.Structural.Generation!=""),hooks:[.Structural.Hooks[]?|select(.Attached)|.Program]|length,err:.Structural.Error,off_warn:[.Warnings[]|select(.ID=="structural-enforcement-off")|.ID]}'
}

pkill -x filemaster-core 2>/dev/null; sleep 1
"$CORE" bpf-teardown 2>/dev/null
rm -rf "$D" /tmp/fm.log /srv/watched /srv/open
mkdir -p "$D" /srv/watched /srv/open
# Fixtures created before enforcement (unlink/rmdir need existing targets).
touch /srv/watched/victim /srv/open/victim
mkdir /srv/watched/rmme /srv/open/rmme

echo "== enforce on /srv/watched (block default) =="
printf '{"filter":{"defaultAction":"block"},"fileaccess":{"structuralEnforcement":"enforce","watchPaths":["+ /srv/watched"]}}' >"$D/config.json"
start || exit 1
diag

echo "-- in-scope (expect denied) --"
rm /srv/watched/victim && echo "UNEXPECTED allowed: unlink"
rmdir /srv/watched/rmme && echo "UNEXPECTED allowed: rmdir"
mkdir /srv/watched/newdir && echo "UNEXPECTED allowed: mkdir"
echo "-- out-of-scope (expect allowed) --"
rm /srv/open/victim && echo "out unlink allowed" || echo "out unlink DENIED?!"
mkdir /srv/open/newdir && echo "out mkdir allowed" || echo "out mkdir DENIED?!"

echo "== SIGKILL: pinned generation keeps enforcing =="
kill -9 "$(cat /tmp/fm.pid)"; sleep 1
pgrep -x filemaster-core >/dev/null && echo "daemon still running?!" || echo "daemon gone"
if rm /srv/watched/victim; then echo "UNEXPECTED allowed"; else echo "ok: still denied after SIGKILL"; fi

echo "== restart: new generation enforcing =="
start || exit 1
diag
if rm /srv/watched/victim; then echo "UNEXPECTED allowed"; else echo "ok: denied under new generation"; fi

echo "== off: detached, reported unprotected =="
kill "$(cat /tmp/fm.pid)" 2>/dev/null; sleep 2; pkill -x filemaster-core; sleep 1
printf '{"filter":{"defaultAction":"block"},"fileaccess":{"structuralEnforcement":"off","watchPaths":["+ /srv/watched"]}}' >"$D/config.json"
start || exit 1
diag
rm /srv/watched/victim && echo "ok: allowed when off" || echo "UNEXPECTED denied when off"
kill "$(cat /tmp/fm.pid)" 2>/dev/null; sleep 2; pkill -x filemaster-core
"$CORE" bpf-teardown 2>/dev/null
echo "== done =="
