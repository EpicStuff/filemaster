//go:build linux && filemaster_test

package fileaccess

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

// socketSource implements Source over a Unix domain socket. The daemon listens;
// an external tool (fake-fanotify) connects, sends JSON events, and receives
// verdict lines back. Only active when FM_FAKE_SOCKET is set at startup.
type socketSource struct {
	ln  net.Listener
	log logger
}

func newSocketSource(path string, log logger) (*socketSource, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("socket source listen %s: %w", path, err)
	}
	log.Info("socket source ready", "path", path)
	return &socketSource{ln: ln, log: log}, nil
}

// socketEvent is the JSON line the fake-fanotify binary sends per event.
type socketEvent struct {
	PID  int32  `json:"pid"`
	Path string `json:"path"`
	Op   string `json:"op"`
	// Note: no "exe" field. The real kernel source never provides one;
	// the profile is resolved from PID via /proc. Any "exe" key in the
	// JSON is ignored.
}

func (s *socketSource) Run(ctx context.Context, handler PendingHandler) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("socket source accept: %w", err)
			}
		}
		go s.handleConn(ctx, conn, handler)
	}
}

func (s *socketSource) handleConn(ctx context.Context, conn net.Conn, handler PendingHandler) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var se socketEvent
		if err := json.Unmarshal(scanner.Bytes(), &se); err != nil {
			s.log.Warn("socket source: bad event JSON", "err", err)
			continue
		}
		// Deliberately mirror the real fanotify source: only PID, Path
		// and Op come off the wire. Exe is left empty so the profile is
		// resolved from the PID via /proc, exactly as in production —
		// tests must therefore supply a real, live PID.
		event := FileEvent{
			PID:  se.PID,
			Path: se.Path,
			Op:   opFromString(se.Op),
		}
		pending := newPendingEvent(&event, func(verdict Verdict) responseResult {
			if _, err := fmt.Fprintf(conn, "%s\n", verdict); err != nil {
				return responseResult{err: err}
			}
			return responseResult{accepted: true}
		})
		if _, err := deliverPendingEvent(ctx, handler, pending); err != nil {
			s.log.Error("socket source event resolution failed", "err", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		s.log.Warn("socket source: connection scan ended with error", "err", err)
	}
}

func opFromString(s string) FileOp {
	switch s {
	case "read":
		return OpRead
	case "write":
		return OpWrite
	case "exec":
		return OpExec
	default:
		return OpOpen
	}
}

func (s *socketSource) SetWatchPaths([]string) error { return nil }
func (s *socketSource) Close() error                 { return s.ln.Close() }
