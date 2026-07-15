package fileaccess

import "context"

// Source produces FileEvents and applies verdicts. Run blocks until ctx
// is done or the source hits an unrecoverable error; intermediate event
// handling happens inline via the supplied Handler. Close releases any
// resources held outside Run -- typically a kernel fd -- and is safe to
// call concurrently with Run.
type Source interface {
	Run(ctx context.Context, handler PendingHandler) error
	Close() error

	// SetWatchPaths reconciles the current mark set with paths: marks
	// new entries, unmarks ones that are gone, leaves the rest alone.
	// Safe to call concurrently with Run. The platform may return an
	// error for an individual path (e.g. unmarkable mount); per-path
	// errors are wrapped and joined so the caller can log them all.
	SetWatchPaths(paths []string) error
}

// reconciliationSource is implemented by platform sources that need a
// separate managed mount-reconciliation loop.
type reconciliationSource interface {
	RunReconciliation(context.Context) error
}

// logger is the small subset of mgr.Manager / mgr.WorkerCtx that sources
// need for diagnostic logging. Keeping it narrow lets the test source
// pass a no-op logger.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// nopLogger discards everything; useful as a default for tests.
type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}
