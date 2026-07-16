package fileaccess

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// LifecycleState describes the shared state of the complete file access
// enforcement pipeline.
type LifecycleState uint32

const defaultControlledShutdownTimeout = 10 * time.Second

const (
	LifecycleRunning LifecycleState = iota
	LifecycleClosing
	LifecycleClosed
)

func (state LifecycleState) String() string {
	switch state {
	case LifecycleRunning:
		return "running"
	case LifecycleClosing:
		return "closing"
	case LifecycleClosed:
		return "closed"
	default:
		return "unknown"
	}
}

var ErrFileAccessClosing = errors.New("file access pipeline is closing")

// PipelineLifecycle is shared by the reader, reconciliation, decision,
// prompt, response, and persistence components. Running activities which can
// publish new work use whileRunning; BeginClosing waits for those short
// publication sections before making Closing visible.
type PipelineLifecycle struct {
	state atomic.Uint32

	transitionMu sync.Mutex
	activityMu   sync.RWMutex

	mu          sync.Mutex
	closingCtx  context.Context
	closingStop context.CancelFunc
	result      error

	closing chan struct{}
	closed  chan struct{}
}

func NewPipelineLifecycle() *PipelineLifecycle {
	return &PipelineLifecycle{
		closing: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (lifecycle *PipelineLifecycle) State() LifecycleState {
	if lifecycle == nil {
		return LifecycleRunning
	}
	return LifecycleState(lifecycle.state.Load())
}

func (lifecycle *PipelineLifecycle) IsRunning() bool {
	return lifecycle.State() == LifecycleRunning
}

func (lifecycle *PipelineLifecycle) Closing() <-chan struct{} {
	if lifecycle == nil {
		return nil
	}
	return lifecycle.closing
}

func (lifecycle *PipelineLifecycle) Closed() <-chan struct{} {
	if lifecycle == nil {
		return nil
	}
	return lifecycle.closed
}

func (lifecycle *PipelineLifecycle) whileRunning(fn func()) bool {
	if lifecycle == nil {
		fn()
		return true
	}
	lifecycle.activityMu.RLock()
	defer lifecycle.activityMu.RUnlock()
	if lifecycle.State() != LifecycleRunning {
		return false
	}
	fn()
	return true
}

// BeginClosing performs the single Running to Closing transition and captures
// the context shared by the complete shutdown sequence.
func (lifecycle *PipelineLifecycle) BeginClosing(ctx context.Context) (context.Context, bool) {
	if lifecycle == nil {
		return ctx, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lifecycle.transitionMu.Lock()
	defer lifecycle.transitionMu.Unlock()
	if lifecycle.State() != LifecycleRunning {
		return lifecycle.ClosingContext(), false
	}

	// Reconciliation, configuration publication, queue admission, and prompt
	// admission hold the read side only for their short publication section.
	// Taking the write side here ensures none can publish after Closing.
	lifecycle.activityMu.Lock()
	lifecycle.mu.Lock()
	lifecycle.closingCtx, lifecycle.closingStop = context.WithCancel(ctx)
	closingCtx := lifecycle.closingCtx
	lifecycle.mu.Unlock()
	lifecycle.state.Store(uint32(LifecycleClosing))
	close(lifecycle.closing)
	lifecycle.activityMu.Unlock()
	return closingCtx, true
}

func (lifecycle *PipelineLifecycle) ClosingContext() context.Context {
	if lifecycle == nil {
		return context.Background()
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.closingCtx == nil {
		return context.Background()
	}
	return lifecycle.closingCtx
}

func (lifecycle *PipelineLifecycle) PublishClosed(result error) {
	if lifecycle == nil {
		return
	}
	lifecycle.transitionMu.Lock()
	defer lifecycle.transitionMu.Unlock()
	if lifecycle.State() == LifecycleClosed {
		return
	}
	lifecycle.mu.Lock()
	lifecycle.result = result
	if lifecycle.closingStop != nil {
		lifecycle.closingStop()
	}
	lifecycle.mu.Unlock()
	lifecycle.state.Store(uint32(LifecycleClosed))
	close(lifecycle.closed)
}

func (lifecycle *PipelineLifecycle) Result() error {
	if lifecycle == nil {
		return nil
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.result
}
