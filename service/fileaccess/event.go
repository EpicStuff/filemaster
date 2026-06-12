package fileaccess

import "context"

// FileOp is the kind of file access being requested.
type FileOp uint8

const (
	// OpOpen is the only op surfaced by the phase-1 fanotify source.
	// Read/Write/Exec come later when we move to FAN_ACCESS_PERM and
	// FAN_OPEN_EXEC_PERM.
	OpOpen FileOp = iota
)

func (op FileOp) String() string {
	switch op {
	case OpOpen:
		return "open"
	default:
		return "unknown"
	}
}

// Verdict is a handler's decision for a single FileEvent.
type Verdict uint8

const (
	VerdictAllow Verdict = iota
	VerdictDeny
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// FileEvent is a single file-access request from a Source. All resolution
// (PID -> exe path, fd -> file path) is the source's responsibility so
// handlers can stay free of /proc and fanotify specifics.
//
// ProfileID / ProfileSource / ProfileName / ProfileLinkedPath are
// optional and only filled in by handlers that resolve a profile
// (ProfileHandler). The fanotify source leaves them empty; prompters
// that surface the event to a UI use them when set and fall back to Exe
// otherwise.
type FileEvent struct {
	PID  int32
	Exe  string
	Path string
	Op   FileOp

	ProfileID         string
	ProfileSource     string
	ProfileName       string
	ProfileLinkedPath string
}

// Handler decides a Verdict for a FileEvent. Implementations must return
// promptly: the kernel is blocking the originating syscall until the
// source writes the verdict back.
//
// The context is the source's run context; handlers that block (e.g.
// waiting for a user response) should select on ctx.Done() to unwind
// during shutdown.
type Handler interface {
	Decide(ctx context.Context, event FileEvent) Verdict
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(context.Context, FileEvent) Verdict

// Decide implements Handler.
func (f HandlerFunc) Decide(ctx context.Context, e FileEvent) Verdict { return f(ctx, e) }

// allowAll is the phase-1 default handler -- log and let everything
// through. Phase 3 swaps this for the profile/endpoint/prompt path.
var allowAll HandlerFunc = func(context.Context, FileEvent) Verdict { return VerdictAllow }
