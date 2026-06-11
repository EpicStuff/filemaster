// Package intel is a scaffolding stub for filemaster.
//
// In upstream Portmaster this package held ~600 LOC of Entity logic: an IP/
// domain/country/ASN object used as the matching key for endpoint rules.
// filemaster does not match against IPs or domains, but the existing
// service/profile/endpoints/* files (kept as dead scaffolding) still take
// *intel.Entity, so this stub exposes the minimum surface they reference.
//
// Delete this package along with the network endpoint files once file-flavored
// endpoints are in place. See FORK_NOTES.md.
package intel

import (
	"context"
	"net"

	"github.com/safing/portmaster/service/network/netutils"
)

// Entity is a placeholder used only to keep the network endpoint matchers
// compiling. No code in this fork populates it, so every Match* against a
// non-nil Entity will fall through to NoMatch.
type Entity struct {
	IP       net.IP
	IPScope  netutils.IPScope
	Domain   string
	Port     uint16
	Protocol uint8
	CNAME    []string
}

// Init is a no-op kept for callers that initialize entities post-mutation.
func (e *Entity) Init(_ int) *Entity { return e }

// DstPort returns the destination port.
func (e *Entity) DstPort() uint16 { return e.Port }

// GetDomain returns the entity's domain.
func (e *Entity) GetDomain(_ context.Context, _ bool) (string, bool) {
	if e.Domain == "" {
		return "", false
	}
	return e.Domain, true
}

// GetASN returns the entity's autonomous-system number, if known.
// Always unknown in this fork.
func (e *Entity) GetASN(_ context.Context) (uint, bool) { return 0, false }

// CountryInfo holds the bare minimum a country-endpoint matcher needs.
type CountryInfo struct {
	Code      string
	Name      string
	Continent struct {
		Code string
		Name string
	}
}

// GetCountryInfo returns the country the entity's IP is located in.
// Always nil in this fork.
func (e *Entity) GetCountryInfo(_ context.Context) *CountryInfo { return nil }

// CNAMECheckEnabled reports whether CNAME chains should be checked during
// endpoint matching.
func (e *Entity) CNAMECheckEnabled() bool { return false }

// EnableCNAMECheck enables CNAME-chain checking.
func (e *Entity) EnableCNAMECheck(_ context.Context, _ bool) {}

// EnableReverseResolving enables reverse-DNS lookups for matching.
func (e *Entity) EnableReverseResolving() {}

// ResolveSubDomainLists enables block-list lookups across sub-domains of the
// entity's domain.
func (e *Entity) ResolveSubDomainLists(_ context.Context, _ bool) {}

// MatchLists reports whether the entity is contained in any of the given
// block lists. Always false in this fork.
func (e *Entity) MatchLists(_ []string) bool { return false }

// ListBlockReason returns the explanation for a list-based block decision.
func (e *Entity) ListBlockReason() string { return "" }
