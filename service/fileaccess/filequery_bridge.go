// Filemaster-specific: wraps a Handler to forward verdicts to the filequery feed.
package fileaccess

import (
	"context"
	"time"

	"github.com/safing/portmaster/service/filequery"
)

type recordingHandler struct {
	inner Handler
	feed  chan<- filequery.FileAccessRecord
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
