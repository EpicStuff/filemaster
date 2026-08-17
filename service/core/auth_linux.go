//go:build linux

package core

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/process"
)

const (
	apiSocketPath = "/run/filemaster/api.sock"

	deniedMsgUnidentified = `%wFailed to identify the requesting process. Reload to try again.`

	deniedMsgSystem = `%wSystem access to the Filemaster API is not permitted.
You can enable the Development Mode to disable API authentication for development purposes.`

	deniedMsgUnauthorized = `%wThe requesting process is not authorized to access the Filemaster API.
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
	flag.Var(&allowedClients, "allowed-clients", "A list of binaries that are allowed to connect to the Filemaster API")
}

type apiPeerPIDContextKey struct{}

// registerAPISocket adds the authenticated native-client transport. The socket
// is world-connectable so the desktop user's process can reach it; access is
// granted only after its kernel-reported PID is checked below.
func registerAPISocket() error {
	listener, err := listenAPISocket(apiSocketPath)
	if err != nil {
		return fmt.Errorf("create API socket: %w", err)
	}

	err = api.RegisterListener(api.Listener{
		Name:        "unix socket API server",
		Listener:    listener,
		ConnContext: withAPIPeerPID,
	})
	if err != nil {
		_ = listener.Close()
		return err
	}
	return nil
}

func listenAPISocket(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("refusing insecure API socket directory %s", dir)
	}

	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket API path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func withAPIPeerPID(ctx context.Context, conn net.Conn) context.Context {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return ctx
	}
	pid, err := peerPID(unixConn)
	if err != nil {
		log.Tracer(ctx).Warningf("core: failed to read API socket peer credentials: %s", err)
		pid = process.UnidentifiedProcessID
	}
	return context.WithValue(ctx, apiPeerPIDContextKey{}, pid)
}

func peerPID(conn *net.UnixConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var controlErr error
	err = rawConn.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	if credentials == nil || credentials.Pid <= 0 {
		return 0, fmt.Errorf("invalid peer PID")
	}
	return int(credentials.Pid), nil
}

func peerPIDFromContext(ctx context.Context) (int, bool) {
	pid, ok := ctx.Value(apiPeerPIDContextKey{}).(int)
	return pid, ok
}

// apiAuthenticator grants PermitSelf to native requests made through the Unix
// socket by a binary in the root-owned install/updates directory (or an
// explicitly allowed client). TCP clients intentionally fall through to the
// API key, session, and Development Mode authentication paths.
func apiAuthenticator(r *http.Request, _ *http.Server) (*api.AuthToken, error) {
	if config.Concurrent.GetAsBool(config.CfgDevModeKey, false)() {
		return &api.AuthToken{Read: api.PermitSelf, Write: api.PermitSelf}, nil
	}

	pid, isUnixSocketRequest := peerPIDFromContext(r.Context())
	if !isUnixSocketRequest {
		return nil, nil
	}

	log.Tracer(r.Context()).Tracef("core: authenticating API socket peer PID %d", pid)
	if err := authenticateAPIProcess(r.Context(), pid); err != nil {
		return nil, err
	}
	return &api.AuthToken{Read: api.PermitSelf, Write: api.PermitSelf}, nil
}

func authenticateAPIProcess(ctx context.Context, pid int) error {
	authenticatedPath := module.instance.BinaryUpdates().GetMainDir()
	if authenticatedPath == "" {
		return fmt.Errorf(deniedMsgMisconfigured, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}
	authenticatedPath, err := filepath.EvalSymlinks(authenticatedPath)
	if err != nil {
		return fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}
	authenticatedPath += string(filepath.Separator)

	if pid <= 0 {
		log.Tracer(ctx).Warningf("core: denying API access: failed to identify process")
		return fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}

	proc, err := process.GetOrFindProcess(ctx, pid)
	if err != nil {
		log.Tracer(ctx).Warningf("core: denying API access: failed to identify process: %s", err)
		return fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}
	switch proc.Pid {
	case process.UnidentifiedProcessID:
		log.Tracer(ctx).Warningf("core: denying API access: failed to identify process")
		return fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	case process.SystemProcessID:
		log.Tracer(ctx).Warningf("core: denying API access: request by system")
		return fmt.Errorf(deniedMsgSystem, api.ErrAPIAccessDeniedMessage) //nolint:stylecheck // message for user
	}

	realPath, err := filepath.EvalSymlinks(proc.Path)
	if err == nil {
		if slices.Contains(allowedClients, realPath) || strings.HasPrefix(realPath, authenticatedPath) {
			return nil
		}
	}

	log.Tracer(ctx).Warningf("core: denying API access to %s (trusted root is %s)", proc.Path, authenticatedPath)
	return fmt.Errorf( //nolint:stylecheck // message for user
		deniedMsgUnauthorized,
		api.ErrAPIAccessDeniedMessage,
		proc.Path,
		authenticatedPath,
	)
}
