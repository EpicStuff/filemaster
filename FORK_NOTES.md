# filemaster — fork notes

Forked from safing/portmaster @ 1219d15 (development branch) on 2026-06-11.
Goal: repurpose Portmaster's per-app prompt/rule machinery for file
read/write access instead of network connections.

## Deleted from upstream

### Whole subsystems
- `spn/` — Safing Privacy Network (onion routing, paid feature). ~32k LOC.
- `windows_kext/`, `windows_core_dll/` — Windows WFP kernel driver. ~1.4 MB.

### Commands
- `cmds/hub`, `cmds/observation-hub`, `cmds/trafficgen` — SPN node binaries.
- `cmds/winkext-test` — Windows kernel-driver tester.
- `cmds/testsuite` — depended on SPN.

### Service packages (whole directories)
- `service/resolver` — DoH/DoT DNS resolver.
- `service/nameserver` — local DNS server intercepting "astray" queries.
- `service/intel/filterlists` — block-list resolution.
- `service/intel/customlists` — user-defined block lists.
- `service/intel/geoip` — country/ASN lookups.
- `service/firewall/interception/dnsmonitor` — DNS sniffing.
- `service/netquery` — connection history SQLite + UI charts.
- `service/splittun` — split-tunneling helpers.
- `service/compat` — network compatibility checks.
- `service/detection` — DGA (domain-generation algorithm) detection.
- `service/interop` (including `interop/ivpn`) — third-party VPN interop.
- `service/firewall` — network packet filter (will be replaced by file-access daemon).
- `service/network` — connection tracking, socket tables, packet parsing.
- `service/intel` (whole package, minus a stub we'll add back) — IP/domain/country entity definitions.
- `service/netenv` — internet location detection, GeoIP-based.

### Firewall sub-files (already covered by deleting `service/firewall`, listed for traceability)
- `service/firewall/dns.go`
- `service/firewall/tunnel.go`
- `service/firewall/split-tunnel.go`
- `service/firewall/bypassing.go`
- `service/firewall/preauth.go`
- `service/firewall/inspection/` (whole subdir)

## Surgical strips (file kept, network bits removed)

- `service/broadcasts/api.go` — dropped `interop/ivpn` and `resolver` imports + the related DB-key delete calls.
- `service/broadcasts/data.go` — rewritten: removed geoip/SPN/access matching data; kept versions/install/config/uptime/current.
- `service/core/core.go` — removed blank-imports of `netenv` and `netquery`.
- `service/core/api.go` — dropped `compat`/`resolver`/`captain` imports + their `AddToDebugInfo` calls.
- `service/process/find.go` — rewritten: kept `GetProcessWithProfile`, stubbed `GetProcessByRequestOrigin`; removed `GetPidOfConnection`, `GetNetworkHost`, and the network/{packet,reference,state,netutils,socket} imports.
- `service/process/special.go` — removed `service/network/socket` import + the init-time PID-constant sanity check that compared to it.

## Design decisions kept across sessions

- **Endpoint stubs (option A):** rather than ripping out all rule-matching code from `service/profile`, we keep the `endpoints` package and all `LayeredProfile.Match*` methods intact and restore tiny stubs of `service/intel.Entity` and `service/network/netutils`. This is dead scaffolding until file-flavored endpoints land — when they do, the IP/domain endpoint files and the stubs go in one sweep. See `/root/.claude/projects/-root-filemaster/memory/decision_endpoint_stubs.md`.

## Compile status

As of 2026-06-11 the tree builds cleanly:

- `go build ./...` exits 0 with no errors.
- `go vet ./...` exits 0 with no warnings.
- `go build -o pm-core ./cmds/portmaster-core/` produces a 26 MB binary.

## Stubs we restored to keep network endpoint matchers compiling

These exist solely so the (now dead) IP/domain/country/ASN/scope matchers under
`service/profile/endpoints/` still compile. They will be deleted in one sweep
when file-flavored endpoints land.

- `service/intel/entity.go` — `Entity` struct with `IP`, `IPScope`, `Domain`,
  `Port`, `Protocol`, `CNAME` fields and stub methods (`Init`, `DstPort`,
  `GetDomain`, `GetASN`, `GetCountryInfo`, `CNAMECheckEnabled`,
  `EnableCNAMECheck`, `EnableReverseResolving`, `ResolveSubDomainLists`,
  `MatchLists`, `ListBlockReason`) that all return zero-values. Plus a
  `CountryInfo` type with `Code`, `Name`, and a nested `Continent`.
- `service/network/netutils/netutils.go` — `IPScope` type, the 8 scope
  constants (`Undefined`, `Invalid`, `HostLocal`, `LinkLocal`, `SiteLocal`,
  `Global`, `LocalMulticast`, `GlobalMulticast`), `IsValidFqdn`.
- `service/network/reference/reference.go` — `GetProtocolName`,
  `GetProtocolNumber`, `GetPortName`, `GetPortNumber`, `IsICMP` — used by the
  endpoint rule parser to recognise `tcp`/`http`/`https` names. Stub returns
  numeric strings and `false` for unknown names.

## More surgical strips (added since previous note)

- `service/instance.go` — full rewrite. Dropped 22 imports of deleted modules
  and SPN; dropped all `*spn/*` fields; dropped the SPN service group; dropped
  `GetEventSPNConnected`/`GetHookSPNConnecting`. Service group is now just
  base modules + core + updates + integration + ui + profile + process +
  status + broadcasts + sync.
- `service/profile/config.go` — dropped `spn/access/account` import;
  `account.FeatureHistory` annotation replaced with empty constant.
- `service/profile/config-update.go` — dropped `intel/filterlists` import
  and its `ResolveListIDs` call.
- `service/profile/profile.go` — dropped `intel/filterlists` import and its
  `ResolveListIDs` call.
- `service/profile/profile-layered.go` — replaced two
  `entity.ListBlockReason()` return values with `nil` (the stub returns
  `string`, not `endpoints.Reason`; both call paths are dead anyway).
- `service/status/status.go` + `module.go` — dropped `netenv` import; removed
  `OnlineStatus` and `CaptivePortal` fields from `SystemStatusRecord`;
  removed online-status change callback and netenv-based debug section.
- `service/debug.go` — removed the SPN-group worker-info loop.
- `cmds/portmaster-core/main.go` — dropped `spn/conf` import + its
  `EnableClient`/`EnableIntegration` calls.
- `cmds/portmaster-core/main_linux.go` — removed `--recover-iptables` flag
  handling (the recovery file was deleted with the rest of `firewall`).
- `cmds/portmaster-core/recover_linux.go` — deleted (depended on
  `firewall/interception`).
- `cmds/integrationtest/` — deleted (network-state tester).
- `service/control/` — deleted whole package (pause/resume orchestration for
  interception + SPN, both gone).

## Tests removed

- `service/profile/endpoints/endpoints_test.go` and `endpoint_test.go` —
  required `intel/geoip`.
- `service/debug_test.go` — referenced `SpnGroup`.
