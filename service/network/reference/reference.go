// Package reference is a scaffolding stub for filemaster.
//
// In upstream Portmaster this package mapped well-known protocol numbers
// (TCP=6, UDP=17, …) and port-name aliases (http=80, https=443, …) to and
// from their numeric form, used during rule parsing. filemaster does not
// parse protocol/port-based endpoint rules at runtime; the IP/domain
// matchers in service/profile/endpoints still compile against this surface
// while we use them as dead scaffolding.
//
// Delete this package along with the network endpoint files once
// file-flavored endpoints are in place. See FORK_NOTES.md.
package reference

import "strconv"

// GetProtocolName returns the printable name for a protocol number, or the
// numeric string if no name is known. In this fork no names are known.
func GetProtocolName(n uint8) string {
	return strconv.Itoa(int(n))
}

// GetProtocolNumber returns the numeric value of a protocol name. In this
// fork every name is unknown.
func GetProtocolNumber(_ string) (uint8, bool) {
	return 0, false
}

// GetPortName returns the printable name for a port number, or the numeric
// string if no name is known.
func GetPortName(p uint16) string {
	return strconv.Itoa(int(p))
}

// GetPortNumber returns the numeric value of a port name. In this fork
// every name is unknown.
func GetPortNumber(_ string) (uint16, bool) {
	return 0, false
}

// IsICMP reports whether the protocol number identifies ICMP or ICMPv6.
func IsICMP(p uint8) bool {
	return p == 1 || p == 58
}
