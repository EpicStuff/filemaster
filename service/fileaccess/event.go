package fileaccess

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
type FileEvent struct {
	PID  int32
	Exe  string
	Path string
	Op   FileOp
}

// Handler decides a Verdict for a FileEvent. Implementations must return
// promptly: the kernel is blocking the originating syscall until the
// source writes the verdict back.
type Handler interface {
	Decide(event FileEvent) Verdict
}

// HandlerFunc adapts a plain function to the Handler interface.
type HandlerFunc func(FileEvent) Verdict

// Decide implements Handler.
func (f HandlerFunc) Decide(e FileEvent) Verdict { return f(e) }

// allowAll is the phase-1 default handler -- log and let everything
// through. Phase 3 swaps this for the profile/endpoint/prompt path.
var allowAll HandlerFunc = func(FileEvent) Verdict { return VerdictAllow }
