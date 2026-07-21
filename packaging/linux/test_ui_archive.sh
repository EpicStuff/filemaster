#!/usr/bin/env bash
set -euo pipefail

make_command=$1
archiver=$2
test_dir=$(mktemp -d)

cleanup() {
	rm -rf "$test_dir"
}
trap cleanup EXIT

mkdir -p "$test_dir/missing-index"
printf '%s\n' 'not the UI entry point' >"$test_dir/missing-index/app.js"
(
	cd "$test_dir/missing-index"
	"$archiver" -a -cf "$test_dir/missing-index.zip" .
)

if "$make_command" --no-print-directory verify-ui-archive UI_ZIP="$test_dir/missing-index.zip" ARCHIVER="$archiver"; then
	echo 'expected archive without index.html to fail validation' >&2
	exit 1
fi

mkdir -p "$test_dir/with-index"
printf '%s\n' '<!doctype html><title>Filemaster</title>' >"$test_dir/with-index/index.html"
(
	cd "$test_dir/with-index"
	"$archiver" -a -cf "$test_dir/with-index.zip" .
)

"$make_command" --no-print-directory verify-ui-archive UI_ZIP="$test_dir/with-index.zip" ARCHIVER="$archiver"
