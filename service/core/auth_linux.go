//go:build linux

package core

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/log"
)

// localhostAuthenticator grants PermitSelf to processes owned by the same UID
// as the daemon, verified via /proc/net/tcp. This prevents other users on the
// same machine from talking to the API, unlike a plain loopback-only check.
func localhostAuthenticator(r *http.Request, _ *http.Server) (*api.AuthToken, error) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, nil
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, nil
	}

	remotePort, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, nil
	}

	uid, err := uidForConnection(ip, uint16(remotePort))
	if err != nil {
		log.Warningf("core: auth: could not resolve UID for %s: %v", r.RemoteAddr, err)
		return nil, nil
	}

	if uid == uint32(os.Getuid()) || uid == uint32(os.Geteuid()) {
		return &api.AuthToken{Read: api.PermitSelf, Write: api.PermitSelf}, nil
	}

	return nil, nil
}

// uidForConnection returns the UID of the process whose socket has local
// address ip:port (i.e., the connecting client's ephemeral-port side).
func uidForConnection(ip net.IP, port uint16) (uint32, error) {
	if ip4 := ip.To4(); ip4 != nil {
		if uid, err := scanTCPFile("/proc/net/tcp", encode4(ip4, port)); err == nil {
			return uid, nil
		}
	}
	if ip6 := ip.To16(); ip6 != nil {
		if uid, err := scanTCPFile("/proc/net/tcp6", encode6(ip6, port)); err == nil {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no /proc/net/tcp entry for %s:%d", ip, port)
}

// encode4 encodes an IPv4 address and port into the /proc/net/tcp rem_address
// format: little-endian 4-byte hex + ":" + big-endian port hex.
func encode4(ip4 []byte, port uint16) string {
	le := binary.LittleEndian.Uint32(ip4)
	return fmt.Sprintf("%08X:%04X", le, port)
}

// encode6 encodes an IPv6 address and port into the /proc/net/tcp6 rem_address
// format: four little-endian 4-byte groups + ":" + big-endian port hex.
func encode6(ip6 []byte, port uint16) string {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		le := binary.LittleEndian.Uint32(ip6[i*4 : i*4+4])
		fmt.Fprintf(&b, "%08X", le)
	}
	fmt.Fprintf(&b, ":%04X", port)
	return b.String()
}

// scanTCPFile scans a /proc/net/tcp or /proc/net/tcp6 file looking for a row
// where the local_address field equals clientAddr (the client's ephemeral port),
// then returns the UID column. The client's socket row has local=ephemeral,
// rem=server; the server's socket row has the same ports reversed but uid=0
// (daemon). We need the client row to get the connecting process's real UID.
func scanTCPFile(path, clientAddr string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		// /proc/net/tcp columns (whitespace-split):
		// 0:sl  1:local  2:rem  3:st  4:tx:rx  5:tr:tm  6:retrnsmt  7:uid  8:timeout  9:inode
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != clientAddr {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid uid %q: %w", fields[7], err)
		}
		return uint32(uid), nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s: no match for %s", path, clientAddr)
}
