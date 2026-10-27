#!/bin/bash
# Flatpak labelling through the real daemon: micro (Flathub) creates its config
# folder at start. Under a block default its flatpak-tagged profile denies the
# mkdir; under a permit default it is allowed. Records name the profile.
set -u
CORE=${CORE:-./filemaster-core}
APP=io.github.zyedidia.micro
D=/tmp/fmf; API=http://127.0.0.1:818/api/v1/fileaccess/diagnostics
S=/root/.var/app/$APP/config
run_micro() { rm -rf "$S/micro"; TERM=xterm timeout 4 script -qec "flatpak run $APP /tmp/fm-flatpak.txt" /dev/null >/dev/null 2>&1; }
for default in block permit; do
	pkill -x filemaster-core; sleep 1; "$CORE" bpf-teardown 2>/dev/null
	rm -rf $D; mkdir -p $D "$S"; rm -rf "$S/micro"
	printf '{"filter":{"defaultAction":"%s"},"fileaccess":{"structuralEnforcement":"enforce","watchPaths":["+ %s"]}}' $default "$S" >$D/config.json
	nohup "$CORE" --data-dir "$D" --log warning --devmode >/tmp/fmf.log 2>&1 &
	for _ in $(seq 90); do curl -sf "$API" | jq -e '.Structural.State=="active"' >/dev/null 2>&1 && break; sleep 1; done
	sleep 2
	# The first run learns nothing (/app paths stay pending); run twice.
	run_micro; run_micro
	if [ -d "$S/micro" ]; then created=yes; else created=no; fi
	echo "default=$default: micro created $S/micro: $created"
	sleep 1
	curl -s -X POST http://127.0.0.1:818/api/v1/filequery/query -H 'Content-Type: application/json' \
		-d '{"pageSize":20,"orderBy":[{"field":"id","desc":true}]}' |
		jq -c '.results[] | select(.path|contains("/micro")) | {op,verdict,path,profile,app_name}' | sort -u | head -4
	curl -s "$API" | jq -c '[.Structural.Undecided[]?|"\(.Reason)/\(.Hook)=\(.Count)"]'
done
pkill -x filemaster-core; sleep 2; "$CORE" bpf-teardown
