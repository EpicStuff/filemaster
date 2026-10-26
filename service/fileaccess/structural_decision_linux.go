//go:build linux

package fileaccess

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safing/portmaster/base/notifications"
	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/filequery"
	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/profile"
)

func (l *structuralLabeller) runDecisions(w *mgr.WorkerCtx) {
	for {
		select {
		case <-w.Ctx().Done():
			return
		case <-l.closed:
			return
		case record := <-l.decisions:
			l.observeDecision(record)
		}
	}
}

func (l *structuralLabeller) observeDecision(record bpflsm.Record) {
	decision := record.Decision
	if decision == nil {
		return
	}
	path, destPath, err := l.enf.DecisionPaths(decision)
	if err != nil {
		l.fa.mgr.Warn("fileaccess: cannot resolve structural decision path", "err", err)
		return
	}
	operation := structuralOperation(decision.Operation)
	verdict := structuralVerdict(decision.Verdict)
	if operation == "" || verdict == "" {
		return
	}

	var scopedID, profileID, appName, exe string
	l.mu.Lock()
	scopedID = l.byLabel[decision.Label]
	l.mu.Unlock()
	if scopedID == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		if p, ok := l.liveProcess(ctx, int32(record.TGID)); ok {
			if layered := p.Profile(); layered != nil {
				if local := layered.LocalProfile(); local != nil {
					scopedID = local.ScopedID()
				}
			}
		}
		cancel()
	}
	if id, ok := strings.CutPrefix(scopedID, string(profile.SourceLocal)+"/"); ok && id != "" {
		profileID = id
		if p, profileErr := profile.GetLocalProfile(id, nil, nil); profileErr == nil && p != nil {
			p.RLock()
			appName = p.Name
			exe = p.PresentationPath
			p.RUnlock()
		}
	}
	if exe == "" {
		if resolved, linkErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", record.TGID)); linkErr == nil {
			exe = resolved
		}
	}
	if appName == "" {
		appName = displayExe(exe)
	}

	rec := filequery.FileAccessRecord{
		At:       time.Now(),
		PID:      int32(record.TGID),
		Exe:      exe,
		Path:     path,
		DestPath: destPath,
		Op:       operation,
		Verdict:  verdict,
		Profile:  scopedID,
		AppName:  appName,
	}
	if source, ok := l.fa.source.(*fanotifySource); ok {
		rec.MountID, rec.MountPath = source.attributeMount(path)
	}
	if handler, ok := l.fa.handler.(*recordingHandler); ok {
		handler.ObserveStructural(rec)
	}
	if decision.Verdict == bpflsm.DecisionDeny {
		l.notifyStructuralDeny(profileID, rec, decision.Reason)
	}
}

func structuralOperation(operation uint32) string {
	switch operation {
	case bpflsm.DecisionDelete:
		return "delete"
	case bpflsm.DecisionCreate:
		return "create"
	case bpflsm.DecisionRename:
		return "rename"
	case bpflsm.DecisionLink:
		return "link"
	default:
		return ""
	}
}

func structuralVerdict(verdict uint32) string {
	switch verdict {
	case bpflsm.DecisionAllow:
		return "allow"
	case bpflsm.DecisionDeny:
		return "deny"
	case bpflsm.DecisionWouldDeny:
		return "would-deny"
	default:
		return ""
	}
}

func structuralReason(reason uint32) string {
	switch reason {
	case 0:
		return "the file path could not be read"
	case 1:
		return "the path was too deep"
	case 2:
		return "the path was too long"
	case 3:
		return "the path is outside the protected roots"
	case 4:
		return "too many path contexts were needed"
	case 5:
		return "the policy evaluation budget was exhausted"
	case 6:
		return "the kernel cannot tell this filesystem's subvolumes apart"
	case 7:
		return "the app was still being identified"
	case 8:
		return "the app could not be identified"
	case 9:
		return "identification took too long"
	case 10:
		return "temporary policy contention"
	case bpflsm.DecisionRuleMatch:
		return "a matching Write rule"
	case bpflsm.DecisionProfileDefault:
		return "the profile default"
	case bpflsm.DecisionNoReason:
		return "the structural policy"
	default:
		return "the structural policy"
	}
}

func (l *structuralLabeller) notifyStructuralDeny(profileID string, rec filequery.FileAccessRecord, reason uint32) {
	if rec.Path == "" {
		return
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", rec.Profile, rec.Op, rec.Path, rec.DestPath)
	id := fmt.Sprintf("fileaccess:structural:%x", sha256.Sum256([]byte(key)))
	if notifications.Get(id) != nil {
		return
	}
	path := rec.Path
	if rec.DestPath != "" {
		path += " → " + rec.DestPath
	}
	message := fmt.Sprintf("%s was blocked from %s %s by %s. Retry the operation after allowing it.", rec.AppName, rec.Op, path, structuralReason(reason))
	n := &notifications.Notification{
		EventID: id,
		Type:    notifications.Info,
		Title:   "File operation blocked",
		Message: message,
	}
	if profileID != "" {
		n.AvailableActions = []*notifications.Action{{ID: ActionAllowAlways, Text: "Allow"}}
		n.SetActionFunction(func(_ context.Context, notification *notifications.Notification) error {
			if notification.SelectedActionID != ActionAllowAlways {
				return nil
			}
			store := &profileRuleStore{source: profile.SourceLocal, id: profileID}
			for _, path := range []string{rec.Path, rec.DestPath} {
				if path == "" {
					continue
				}
				if err := store.AppendRule(OpWrite, FormatLiteralRule(path, VerdictAllow)); err != nil {
					return err
				}
			}
			l.apply()
			return nil
		})
	}
	notifications.Notify(n)
}
