package fileaccess

import "context"

// FileOp is the kind of file access being requested. In the current release the
// fanotify source only ever produces OpOpen (FAN_OPEN_PERM) and OpExec
// (FAN_OPEN_EXEC_PERM): nothing emits a distinct Read or Write event yet.
//
// That is a gap in this package, not a kernel limitation. The fd delivered with
// a perm event is opened with the listener's event_f_flags, so it never reflects
// the application's access mode -- but the calling thread stays frozen inside
// openat while the event is pending, so the requested mode and O_TRUNC can be
// read from arg2 of /proc/<tid>/syscall. Doing that safely needs FAN_REPORT_TID
// (without it metadata.pid is the tgid, whose main thread sits in an unrelated
// syscall whose arg2 is not open flags) and a check that the syscall really is
// openat before arg2 is trusted. openat2 keeps its flags in a userspace struct
// open_how rather than a register, and io_uring opens leave no openat frame to
// read; both have to fail conservative.
//
// What stock fanotify genuinely cannot do is grant a downgrade: a perm response
// is Allow or Deny, so an open requesting write can be refused outright but not
// quietly stripped to read-only. Allow-read-only needs a different backend.
//
// OpRead and OpWrite are retained as internal rule-scope identities, not as
// runtime events: OpRead is the scope of the Access (Read) rule list that
// governs opens (see ruleScopeOp), and OpWrite is the scope of the Write rule
// list, whose storage and plumbing are kept for the future Write engine even
// though nothing emits a write event yet.
type FileOp uint8

const (
	// OpOpen is fired by FAN_OPEN_PERM -- any open()/opendir() the kernel
	// reports that isn't an exec open. It is the current File/Folder Access
	// event and is scoped to the Access (Read) rule list.
	OpOpen FileOp = iota
	// OpRead is the scope identity of the Access (Read) rule list. No runtime
	// source emits it now (FAN_ACCESS_PERM was removed); OpOpen folds to it for
	// rule matching and persistence. It becomes a distinct Read event once opens
	// are classified by their requested access mode.
	OpRead
	// OpWrite is the scope identity of the (currently hidden) Write rule list.
	// No runtime source emits it; it is retained so the future Write evaluation
	// engine can be built and unit-tested before write enforcement lands.
	OpWrite
	// OpExec is fired by FAN_OPEN_EXEC_PERM -- the kernel opening a file for
	// execve(). Always enabled.
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
	PID   int32
	Exe   string
	Path  string
	Op    FileOp
	IsDir bool // FAN_ONDIR for real fanotify sources.

	// MountID / MountPath attribute the event to the protected mount that was
	// active when the decision occurred. The
	// fanotify source fills them from its mount-reconciliation state; other
	// sources leave them zero. A zero MountID with an empty MountPath means the
	// mount is unknown (e.g. reconciliation was pending or no active mount
	// contained the path) -- attribution is never guessed from an unrelated path.
	MountID   int
	MountPath string

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

// allowAll is the initial handler -- log and let everything through. Module
// wiring replaces it with the profile/prompt path via SetHandler.
var allowAll HandlerFunc = func(context.Context, *FileEvent) Verdict { return VerdictAllow }
