package fileaccess

import "context"

// FileOp is the kind of file access being requested. The fanotify
// source decodes the perm-event mask into one of these; the Linux
// kernel itself doesn't surface a "write" distinction at perm-event
// time (the syscall hasn't completed yet, so we can't inspect open
// flags on the new fd). The fake socket source can still emit OpWrite
// for end-to-end tests that model a write attempt explicitly.
type FileOp uint8

const (
	// OpOpen is fired by FAN_OPEN_PERM -- any open() the kernel
	// reports that isn't matched by a more-specific perm event.
	OpOpen FileOp = iota
	// OpRead is fired by FAN_ACCESS_PERM -- a read() against the
	// watched file. Only enabled when the InterceptReads config
	// option is on, because FAN_ACCESS_PERM fires per syscall and
	// can be very chatty.
	OpRead
	// OpWrite is emitted by test/fake sources that model a user-level
	// write attempt explicitly.
	OpWrite
	// OpExec is fired by FAN_OPEN_EXEC_PERM -- the kernel opening
	// a file for execve(). Always enabled.
	OpExec
)

func (op FileOp) String() string {
	switch op {
	case OpOpen:
		return "open"
	case OpRead:
		return "read"
	case OpWrite:
		return "write"
	case OpExec:
		return "exec"
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

	// ProcessIdentity is stable for the lifetime of a resolved process. It is
	// used only for the unidentified prompt bucket, where there is no profile
	// identity available to safely group requests.
	ProcessIdentity string

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
// The event is passed by pointer so handlers in the chain can enrich it
// in place (e.g. ProfileHandler stamps the resolved profile metadata) and
// have those mutations visible to outer handlers such as the filequery
// recorder. This mirrors how portmaster threads *Connection through its
// firewall handler chain.
type Handler interface {
	Decide(ctx context.Context, event *FileEvent) Verdict
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(context.Context, *FileEvent) Verdict

// Decide implements Handler.
func (f HandlerFunc) Decide(ctx context.Context, e *FileEvent) Verdict { return f(ctx, e) }

// allowAll is the phase-1 default handler -- log and let everything
// through. Phase 3 swaps this for the profile/endpoint/prompt path.
var allowAll HandlerFunc = func(context.Context, *FileEvent) Verdict { return VerdictAllow }
