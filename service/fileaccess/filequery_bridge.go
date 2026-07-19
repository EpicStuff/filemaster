// Filemaster-specific: wraps a Handler to forward verdicts to the filequery feed.
package fileaccess

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/service/filequery"
)

type recordingHandler struct {
	inner   Handler
	feed    chan<- filequery.FileAccessRecord
	dropped atomic.Uint64
}

// ObservationDiagnostics reports the state of the observation (filequery) feed.
// Enforcement runs ahead of observation, so a full feed drops records rather
// than blocking a verdict; those drops are counted here so silent record loss
// is visible (§12.4/§12.5, §15.20/§15.21).
type ObservationDiagnostics struct {
	QueueDepth    int
	QueueCapacity int
	Dropped       uint64
}

func (h *recordingHandler) ObservationDiagnostics() ObservationDiagnostics {
	return ObservationDiagnostics{
		QueueDepth:    len(h.feed),
		QueueCapacity: cap(h.feed),
		Dropped:       h.dropped.Load(),
	}
}

// NewRecordingHandler wraps inner so every verdict is forwarded to feed.
func NewRecordingHandler(inner Handler, feed chan<- filequery.FileAccessRecord) Handler {
	return &recordingHandler{inner: inner, feed: feed}
}

func (h *recordingHandler) DecisionHandler() Handler {
	return h.inner
}

func (h *recordingHandler) Observe(e *FileEvent, verdict Verdict) {
	profile := e.ProfileSource + "/" + e.ProfileID
	rec := filequery.FileAccessRecord{
		At:      time.Now(),
		PID:     e.PID,
		Exe:     e.Exe,
		Path:    e.Path,
		Op:      e.Op.String(),
		Verdict: verdictString(verdict),
		Profile: profile,
		AppName: e.ProfileName,
	}
	select {
	case h.feed <- rec:
	default:
		h.dropped.Add(1)
	}
}

func (h *recordingHandler) Decide(ctx context.Context, e *FileEvent) Verdict {
	verdict := h.inner.Decide(ctx, e)
	h.Observe(e, verdict)
	return verdict
}

func verdictString(v Verdict) string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictDeny:
		return "deny"
	default:
		return "allow"
	}
}
