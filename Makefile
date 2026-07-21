SHELL := /usr/bin/env bash

DIST := dist
GOOS := linux
GOARCH ?= $(shell go env GOARCH)
PLATFORM := $(GOOS)_$(GOARCH)
UI_DIR := desktop/angular
TAURI_DIR := desktop/tauri/src-tauri
ARCHIVER := bsdtar
NODE_BIN ?=
NODE_PATH := $(if $(NODE_BIN),$(NODE_BIN):)
CORE := $(DIST)/$(PLATFORM)/portmaster-core
APP := $(DIST)/$(PLATFORM)/portmaster
UI_ZIP := $(DIST)/all/filemaster.zip
ASSETS_ZIP := $(DIST)/all/assets.zip
INTEL_DIR := $(DIST)/intel
UPDATEMGR := $(DIST)/$(PLATFORM)/updatemgr
INSTALL_DIR ?= /opt/filemaster
DATA_DIR ?= /var/lib/filemaster
BIN_DIR ?= /usr/local/bin
SERVICE_DIR ?= /etc/systemd/system
SERVICE_FILE := $(SERVICE_DIR)/filemaster.service

.DEFAULT_GOAL := build
.PHONY: assets build clean core help install intel package stage tauri tauri-ui test test-fake test-ui-archive ui ui-deps verify-ui-archive

help:
	@printf '%s\n' 'Filemaster native build targets:' \
		'  make build    Build the core, UI bundle, assets, and desktop app.' \
		'  make install  Build and install the core, UI, payloads, and systemd unit.' \
		'  make package  Build Linux .deb/.rpm packages through Tauri.' \
		'  make test     Run production and fake-source Go tests.' \
		'  Override install locations with INSTALL_DIR, DATA_DIR, BIN_DIR, and SERVICE_DIR.' \
		'  make clean    Remove generated artifacts.'

build: core ui assets tauri

install: build
	sudo install -d -m 0755 "$(INSTALL_DIR)" "$(BIN_DIR)" "$(SERVICE_DIR)"
	sudo install -m 0755 "$(CORE)" "$(INSTALL_DIR)/portmaster-core"
	sudo install -m 0755 "$(APP)" "$(INSTALL_DIR)/filemaster"
	sudo install -m 0644 "$(UI_ZIP)" "$(INSTALL_DIR)/filemaster.zip"
	sudo install -m 0644 "$(ASSETS_ZIP)" "$(INSTALL_DIR)/assets.zip"
	sudo install -d -m 0750 "$(DATA_DIR)"
	@sed -e 's|/opt/filemaster|$(INSTALL_DIR)|g' -e 's|/var/lib/filemaster|$(DATA_DIR)|g' \
		packaging/linux/filemaster.service | sudo tee "$(SERVICE_FILE)" >/dev/null
	sudo chmod 0644 "$(SERVICE_FILE)"
	@printf '%s\n' '#!/bin/sh' 'exec "$(INSTALL_DIR)/filemaster" --data="$(INSTALL_DIR)" "$$@"' \
		| sudo tee "$(BIN_DIR)/filemaster" >/dev/null
	sudo chmod 0755 "$(BIN_DIR)/filemaster"
	@if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then \
		sudo systemctl daemon-reload; \
	else \
		echo 'Installed filemaster.service; systemd is not running, so reload it on the target host.'; \
	fi
core:
	@mkdir -p "$(dir $(CORE))"
	go build -o "$(CORE)" ./cmds/portmaster-core

ui-deps:
	cd "$(UI_DIR)" && PATH="$(NODE_PATH)$$PATH" npm install

ui: ui-deps
	cd "$(UI_DIR)" && PATH="$(NODE_PATH)$$PATH" npm run build
	@mkdir -p "$(dir $(UI_ZIP))"
	(cd "$(UI_DIR)/dist" && "$(ARCHIVER)" -a -cf "$(abspath $(UI_ZIP))" .)
	$(MAKE) --no-print-directory verify-ui-archive

verify-ui-archive:
	@test -f "$(UI_ZIP)" || { echo "missing required UI archive: $(UI_ZIP)" >&2; exit 1; }
	@"$(ARCHIVER)" -tf "$(UI_ZIP)" | grep -Eq '^\.?/?index\.html$$' || { echo "required UI archive entry missing: index.html in $(UI_ZIP)" >&2; exit 1; }
	@{ "$(ARCHIVER)" -xOf "$(UI_ZIP)" ./index.html >/dev/null 2>&1 || "$(ARCHIVER)" -xOf "$(UI_ZIP)" index.html >/dev/null 2>&1; } || { echo "required UI archive entry is unreadable: index.html in $(UI_ZIP)" >&2; exit 1; }

assets:
	@mkdir -p "$(dir $(ASSETS_ZIP))"
	(cd assets/data && "$(ARCHIVER)" -a -cf "$(abspath $(ASSETS_ZIP))" .)

intel:
	@mkdir -p "$(dir $(UPDATEMGR))" "$(INTEL_DIR)"
	go build -o "$(UPDATEMGR)" ./cmds/updatemgr
	"$(UPDATEMGR)" download https://updates.safing.io/intel.v3.json "$(INTEL_DIR)"

tauri-ui: ui-deps
	cd "$(UI_DIR)" && PATH="$(NODE_PATH)$$PATH" npm run build-tauri

tauri: tauri-ui
	cd "$(TAURI_DIR)" && cargo tauri build --no-bundle
	@mkdir -p "$(dir $(APP))"
	cp "$(TAURI_DIR)/target/release/portmaster" "$(APP)"

stage: core ui assets intel tauri-ui
	@mkdir -p "$(TAURI_DIR)/binary"
	cp "$(CORE)" "$(TAURI_DIR)/binary/portmaster-core"
	cp "$(UI_ZIP)" "$(TAURI_DIR)/binary/filemaster.zip"
	cp "$(ASSETS_ZIP)" "$(TAURI_DIR)/binary/assets.zip"
	@mkdir -p "$(TAURI_DIR)/intel"
	cp -a "$(INTEL_DIR)/." "$(TAURI_DIR)/intel/"

package: stage
	cd "$(TAURI_DIR)" && cargo tauri bundle
	@mkdir -p "$(DIST)/$(PLATFORM)/packages"
	find "$(TAURI_DIR)/target/release/bundle" -type f \( -name '*.deb' -o -name '*.rpm' \) -exec cp {} "$(DIST)/$(PLATFORM)/packages" \;

test:
	go test ./...
	$(MAKE) test-fake
	$(MAKE) test-ui-archive

test-fake:
	go test -tags filemaster_test ./service/fileaccess

test-ui-archive:
	packaging/linux/test_ui_archive.sh "$(MAKE)" "$(ARCHIVER)"

clean:
	rm -rf "$(DIST)" "$(TAURI_DIR)/binary" "$(TAURI_DIR)/target"
