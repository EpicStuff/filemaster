// Package netutils is a scaffolding stub for filemaster.
//
// Upstream Portmaster used this package extensively (~600 LOC) to classify
// IP-scope of incoming packets, parse remote addresses, validate FQDNs, etc.
// filemaster does not deal with packets — these symbols only exist because
// the network-flavored Endpoint matchers under service/profile/endpoints still
// reference them while we use those matchers as dead scaffolding (see
// FORK_NOTES.md → "Stub-scaffolding decision (option A)").
//
// Delete this package along with the network endpoint files once file-flavored
// endpoints are in place.
package netutils

import "strings"

// IPScope is a classification of an IP address by network scope.
// In the original Portmaster this was set by ClassifyIP during packet ingest.
// In this fork no code sets it; matchers checking IPScope will always read
// Undefined.
type IPScope uint8

// IP scope classifications.
const (
	Undefined IPScope = iota
	Invalid
	HostLocal
	LinkLocal
	SiteLocal
	Global
	LocalMulticast
	GlobalMulticast
)

// IsGlobal reports whether the scope is one of the global classifications.
func (s IPScope) IsGlobal() bool {
	switch s {
	case Global, GlobalMulticast:
		return true
	default:
		return false
	}
}

// IsLocalhost reports whether the scope is host-local.
func (s IPScope) IsLocalhost() bool {
	return s == HostLocal
}

// IsValidFqdn loosely validates an FQDN string. The original implementation
// used the publicsuffix list and a stricter grammar; this stub keeps just
// enough to satisfy callers that parse domain rules at startup.
func IsValidFqdn(domain string) bool {
	if domain == "" {
		return false
	}
	for _, r := range domain {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	if strings.Contains(domain, "..") {
		return false
	}
	return true
}
