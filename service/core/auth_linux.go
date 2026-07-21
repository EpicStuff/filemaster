//go:build linux

// Ported from service/firewall/api.go and service/firewall/module.go.
// Only change to the ported policy: upstream identified the connecting process
// via the kernel network monitor (process.GetPidOfConnection), which was removed
// with the network stack. That single step is replaced with a /proc-based lookup
// (/proc/net/tcp → socket inode → /proc/*/fd → PID). The dev-mode and loopback
// checks use stdlib in place of the deleted netenv/netutils/packet helpers.

package core

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/process"
)

const (
	deniedMsgUnidentified = `%wFailed to identify the requesting process. Reload to try again.`

	deniedMsgSystem = `%wSystem access to the Portmaster API is not permitted.
You can enable the Development Mode to disable API authentication for development purposes.`

	deniedMsgUnauthorized = `%wThe requesting process is not authorized to access the Portmaster API.
Checked process paths:
%s

The authorized root path is %s.
You can enable the Development Mode to disable API authentication for development purposes.
For production use please create an API key in the settings.`

	deniedMsgMisconfigured = `%wThe authentication system is misconfigured.`
)

type stringSliceFlag []string

func (ss *stringSliceFlag) String() string {
	return strings.Join(*ss, ":")
}

func (ss *stringSliceFlag) Set(value string) error {
	*ss = append(*ss, filepath.Clean(value))
	return nil
}

var allowedClients stringSliceFlag

func init() {
	flag.Var(&allowedClients, "allowed-clients", "A list of binaries that are allowed to connect to the Portmaster API")
}

// apiAuthenticator grants PermitSelf to API requests coming from a process whose
// executable lives under the root-owned install/updates directory (or an
// explicitly allowed client), verified by identifying the connecting process via
// /proc. Development Mode disables the check for local development.
func apiAuthenticator(r *http.Request, _ *http.Server) (*api.AuthToken, error) {
	// Development Mode disables API authentication (e.g. for `ng serve` on :4200).
	if config.Concurrent.GetAsBool(config.CfgDevModeKey, false)() {
		return &api.AuthToken{Read: api.PermitSelf, Write: api.PermitSelf}, nil
	}

	// The API is bound to loopback only; identify the connecting process by its
	// ephemeral (remote) address.
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, nil
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil || !remoteIP.IsLoopback() {
		// Not a local request; return to caller that it was not handled.
		return nil, nil
	}
	remotePort, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, nil
	}

	log.Tracer(r.Context()).Tracef("core: authenticating API request from %s", r.RemoteAddr)

	// It is important that this works, retry 5 times: every 500ms for 2.5s.
	var retry bool
	for range 5 {
		retry, err = authenticateAPIRequest(r.Context(), remoteIP, uint16(remotePort))
		if !retry {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}

	return &api.AuthToken{Read: api.PermitSelf, Write: api.PermitSelf}, nil
}

func authenticateAPIRequest(ctx context.Context, ip net.IP, port uint16) (retry bool, err error) {
	var procsChecked []string
	var originalPid int

	// Get authenticated path.
	authenticatedPath := module.instance.BinaryUpdates().GetMainDir()
	if authenticatedPath == "" {
		return false, fmt.Errorf(deniedMsgMisconfigured, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}
	// Get real path.
	authenticatedPath, err = filepath.EvalSymlinks(authenticatedPath)
	if err != nil {
		return false, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}
	// Add filepath separator to confine to directory.
	authenticatedPath += string(filepath.Separator)

	// Get process of request.
	pid := pidFromLoopbackConn(ip, port)
	if pid < 0 {
		return false, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}
	proc, err := process.GetOrFindProcess(ctx, pid)
	if err != nil {
		log.Tracer(ctx).Debugf("core: failed to get process of api request: %s", err)
		originalPid = process.UnidentifiedProcessID
	} else {
		originalPid = proc.Pid
		var previousPid int

		// Find parent for up to two levels, if we don't match the path.
		checkLevels := 2
	checkLevelsLoop:
		for i := range checkLevels + 1 {
			// Check for eligible path.
			switch proc.Pid {
			case process.UnidentifiedProcessID, process.SystemProcessID:
				break checkLevelsLoop
			default: // normal process
				// Check if the requesting process is in database root / updates dir.
				if realPath, err := filepath.EvalSymlinks(proc.Path); err == nil {

					// check if the client has been allowed by flag
					if slices.Contains(allowedClients, realPath) {
						return false, nil
					}

					if strings.HasPrefix(realPath, authenticatedPath) {
						return false, nil
					}
				}
			}

			// Add checked path to list.
			procsChecked = append(procsChecked, proc.Path)

			// Get the parent process.
			if i < checkLevels {
				// save previous PID
				previousPid = proc.Pid

				// get parent process
				proc, err = process.GetOrFindProcess(ctx, proc.ParentPid)
				if err != nil {
					log.Tracer(ctx).Debugf("core: failed to get parent process of api request: %s", err)
					break
				}

				// abort if we are looping
				if proc.Pid == previousPid {
					// this also catches -1 pid loops
					break
				}
			}
		}
	}

	switch originalPid {
	case process.UnidentifiedProcessID:
		log.Tracer(ctx).Warningf("core: denying api access: failed to identify process")
		return true, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user

	case process.SystemProcessID:
		log.Tracer(ctx).Warningf("core: denying api access: request by system")
		return false, fmt.Errorf(deniedMsgSystem, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user

	default: // normal process
		log.Tracer(ctx).Warningf("core: denying api access to %s - also checked %s (trusted root is %s)", procsChecked[0], strings.Join(procsChecked[1:], " "), authenticatedPath)
		return false, fmt.Errorf( //nolint:stylecheck // message for user
			deniedMsgUnauthorized,
			api.ErrAPIAccessDeniedMessage,
			strings.Join(procsChecked, "\n"),
			authenticatedPath,
		)
	}
}

// pidFromLoopbackConn identifies the PID owning the loopback client socket at
// ip:port by mapping its socket inode (from /proc/net/tcp) to the process that
// holds it (via /proc/*/fd). Returns -1 if it cannot be resolved.
func pidFromLoopbackConn(ip net.IP, port uint16) int {
	inode, err := inodeForConnection(ip, port)
	if err != nil {
		return -1
	}
	pid, err := pidForInode(inode)
	if err != nil {
		return -1
	}
	return pid
}

// inodeForConnection returns the socket inode of the process whose socket has
// local address ip:port (i.e., the connecting client's ephemeral-port side).
func inodeForConnection(ip net.IP, port uint16) (string, error) {
	if ip4 := ip.To4(); ip4 != nil {
		if inode, err := scanTCPFile("/proc/net/tcp", encode4(ip4, port)); err == nil {
			return inode, nil
		}
	}
	if ip6 := ip.To16(); ip6 != nil {
		if inode, err := scanTCPFile("/proc/net/tcp6", encode6(ip6, port)); err == nil {
			return inode, nil
		}
	}
	return "", fmt.Errorf("no /proc/net/tcp entry for %s:%d", ip, port)
}

// encode4 encodes an IPv4 address and port into the /proc/net/tcp local_address
// format: little-endian 4-byte hex + ":" + big-endian port hex.
func encode4(ip4 []byte, port uint16) string {
	le := binary.LittleEndian.Uint32(ip4)
	return fmt.Sprintf("%08X:%04X", le, port)
}

// encode6 encodes an IPv6 address and port into the /proc/net/tcp6 local_address
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

// scanTCPFile scans a /proc/net/tcp or /proc/net/tcp6 file for the row whose
// local_address equals clientAddr (the client's ephemeral port) and returns the
// socket inode column.
func scanTCPFile(path, clientAddr string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		// /proc/net/tcp columns (whitespace-split):
		// 0:sl 1:local 2:rem 3:st 4:tx:rx 5:tr:tm 6:retrnsmt 7:uid 8:timeout 9:inode
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[1] != clientAddr {
			continue
		}
		return fields[9], nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s: no match for %s", path, clientAddr)
}

// pidForInode returns the PID of the process holding the socket with the given
// inode, by scanning /proc/<pid>/fd for a symlink to socket:[<inode>].
func pidForInode(inode string) (int, error) {
	target := "socket:[" + inode + "]"

	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, d := range procDirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue // not a PID directory
		}
		fdDir := filepath.Join("/proc", d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process gone or not readable
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("no process owns socket inode %s", inode)
}
