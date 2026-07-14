package fileaccess

import (
	"context"
	"testing"

	"github.com/safing/portmaster/service/filequery"
)

// TestRecordingHandlerRecordsEnrichedProfile is the regression test for the
// value-semantics bug that stampExeProfile used to paper over: an inner
// handler resolves the profile and stamps it onto the event; because the
// event is passed by pointer, those mutations must be visible to the
// recording handler so the filequery row carries the real profile — not "/".
func TestRecordingHandlerRecordsEnrichedProfile(t *testing.T) {
	feed := make(chan filequery.FileAccessRecord, 1)

	// inner mimics ProfileHandler: it enriches the shared event in place.
	inner := HandlerFunc(func(_ context.Context, e *FileEvent) Verdict {
		e.Exe = "/usr/bin/sleep"
		e.ProfileSource = "local"
		e.ProfileID = "PTVabc123"
		e.ProfileName = "Sleep"
		return VerdictDeny
	})

	h := NewRecordingHandler(inner, feed)

	v := h.Decide(context.Background(), &FileEvent{PID: 42, Path: "/tmp/secret.txt", Op: OpWrite})
	if v != VerdictDeny {
		t.Fatalf("verdict = %s, want deny", v)
	}

	select {
	case rec := <-feed:
		if rec.Profile != "local/PTVabc123" {
			t.Errorf("record profile = %q, want %q (source+id, prefixed exactly once)", rec.Profile, "local/PTVabc123")
		}
		if rec.AppName != "Sleep" {
			t.Errorf("record app_name = %q, want %q", rec.AppName, "Sleep")
		}
		if rec.Exe != "/usr/bin/sleep" {
			t.Errorf("record exe = %q, want /usr/bin/sleep (resolved by inner)", rec.Exe)
		}
		if rec.Op != "write" || rec.Verdict != "deny" {
			t.Errorf("record op/verdict = %q/%q, want write/deny", rec.Op, rec.Verdict)
		}
	default:
		t.Fatal("no record was fed to filequery")
	}
}

// TestRecordingHandlerUnresolvedProfileIsBare records the honest "/" bucket
// when the inner handler could not resolve a profile (e.g. dead PID). No
// synthetic exe-derived identity is invented.
func TestRecordingHandlerUnresolvedProfileIsBare(t *testing.T) {
	feed := make(chan filequery.FileAccessRecord, 1)

	inner := HandlerFunc(func(_ context.Context, _ *FileEvent) Verdict {
		return VerdictAllow
	})

	h := NewRecordingHandler(inner, feed)
	h.Decide(context.Background(), &FileEvent{PID: 1, Path: "/x", Op: OpRead})

	select {
	case rec := <-feed:
		if rec.Profile != "/" {
			t.Errorf("unresolved profile = %q, want %q", rec.Profile, "/")
		}
		if rec.AppName != "" {
			t.Errorf("unresolved app_name = %q, want empty", rec.AppName)
		}
	default:
		t.Fatal("no record was fed to filequery")
	}
}
