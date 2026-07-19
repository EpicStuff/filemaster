package fileaccess

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	defaultDecisionWorkers       = 4
	defaultDecisionQueueCapacity = 64
	defaultOutstandingEventLimit = 128
	defaultProfileAskLimit       = 4
)

// DecisionPipelineConfig bounds work held after fanotify has transferred an
// event to userspace. It is intentionally backend-configurable now; matching
// user-facing settings are introduced with the diagnostics/UI phase.
type DecisionPipelineConfig struct {
	Workers            int
	QueueCapacity      int
	OutstandingLimit   int64
	PerProfileAskLimit int
}

func DefaultDecisionPipelineConfig() DecisionPipelineConfig {
	return DecisionPipelineConfig{
		Workers:            defaultDecisionWorkers,
		QueueCapacity:      defaultDecisionQueueCapacity,
		OutstandingLimit:   defaultOutstandingEventLimit,
		PerProfileAskLimit: defaultProfileAskLimit,
	}
}

func (c DecisionPipelineConfig) normalized() DecisionPipelineConfig {
	defaults := DefaultDecisionPipelineConfig()
	if c.Workers <= 0 {
		c.Workers = defaults.Workers
	}
	if c.QueueCapacity <= 0 {
		c.QueueCapacity = defaults.QueueCapacity
	}
	if c.OutstandingLimit <= 0 {
		c.OutstandingLimit = defaults.OutstandingLimit
	}
	if c.PerProfileAskLimit <= 0 {
		c.PerProfileAskLimit = defaults.PerProfileAskLimit
	}
	return c
}

// DecisionPipelineDiagnostics exposes bounded-pipeline state without adding
// the broader metrics surface planned for Phase 8.
type DecisionPipelineDiagnostics struct {
	QueueDepth              int
	PeakQueueDepth          int64
	Workers                 int
	ActiveWorkers           int64
	ExpectedWorkers         int64
	ExitedWorkers           int64
	ActiveDecisions         int64
	Outstanding             int64
	PendingAsk              int
	PendingAskByProfile     map[string]int
	Closing                 bool
	QueueSaturationDenies   uint64
	OutstandingBudgetDenies uint64
	ProfileAskBudgetDenies  uint64
}

type postResponseDecisionHandler interface {
	DecideForResponse(context.Context, *FileEvent) (Verdict, func())
}

type responseObserver interface {
	DecisionHandler() Handler
	Observe(*FileEvent, Verdict)
}

type processMappingRefresher interface {
	RefreshProcessMapping(context.Context, int32) error
}

type pendingDecisionHandler interface {
	DecidePending(context.Context, PendingEvent) (handled, handedOff, decided bool, verdict Verdict, afterResponse func())
}

type decisionWork struct {
	pending PendingEvent
}

// DecisionPipeline is one bounded queue serviced by a fixed worker pool. The
// reader transfers ownership into the queue and never waits for profile lookup,
// prompting, persistence, or observation work.
type DecisionPipeline struct {
	config    DecisionPipelineConfig
	handler   Handler
	observe   func(*FileEvent, Verdict)
	queue     chan *decisionWork
	lifecycle *PipelineLifecycle

	started         atomic.Bool
	activeWorkers   atomic.Int64
	expectedWorkers atomic.Int64
	exitedWorkers   atomic.Int64
	activeDecisions atomic.Int64

	outstanding atomic.Int64
	peakQueue   atomic.Int64
	queueDenied atomic.Uint64
	limitDenied atomic.Uint64
	askDenied   atomic.Uint64

	activeMu sync.Mutex
	active   map[*decisionWork]struct{}
	changed  chan struct{}

	askMu      sync.Mutex
	pendingAsk map[string]int
}

func NewDecisionPipeline(handler Handler, config DecisionPipelineConfig) *DecisionPipeline {
	return newDecisionPipeline(handler, config, NewPipelineLifecycle())
}

func newDecisionPipeline(handler Handler, config DecisionPipelineConfig, lifecycle *PipelineLifecycle) *DecisionPipeline {
	config = config.normalized()
	if lifecycle == nil {
		lifecycle = NewPipelineLifecycle()
	}
	pipeline := &DecisionPipeline{
		config:     config,
		handler:    handler,
		queue:      make(chan *decisionWork, config.QueueCapacity),
		lifecycle:  lifecycle,
		active:     make(map[*decisionWork]struct{}),
		changed:    make(chan struct{}, 1),
		pendingAsk: make(map[string]int),
	}
	if observer, ok := handler.(responseObserver); ok {
		pipeline.handler = observer.DecisionHandler()
		pipeline.observe = observer.Observe
	}
	if handler, ok := pipeline.handler.(*ProfileHandler); ok {
		handler.setLifecycle(lifecycle)
		handler.setPromptAdmission(pipeline.acquireAsk)
		coordinator := newPromptCoordinator(handler.prompter, handler.timeout, pipeline.acquireAsk, pipeline.finishTransferredPromptEvent, lifecycle)
		coordinator.complete = pipeline.releaseOutstanding
		handler.setPromptCoordinator(coordinator)
	}
	return pipeline
}

func (p *DecisionPipeline) Config() DecisionPipelineConfig {
	return p.config
}

// Start launches exactly the configured number of workers. It is convenient
// for focused tests; the module uses Run so its manager owns worker lifetimes.
// Activate permits reader admission once production has registered its fixed
// workers. It does not create any goroutine.
func (p *DecisionPipeline) Activate() {
	if p.started.CompareAndSwap(false, true) {
		p.expectedWorkers.Store(int64(p.config.Workers))
		p.signalChanged()
	}
}

func (p *DecisionPipeline) Start(ctx context.Context) {
	if !p.started.CompareAndSwap(false, true) {
		return
	}
	p.expectedWorkers.Store(int64(p.config.Workers))
	p.signalChanged()
	for range p.config.Workers {
		go p.Run(ctx)
	}
}

// Run services queue work in one fixed worker. It must be called exactly once
// per configured worker by production wiring.
func (p *DecisionPipeline) Run(ctx context.Context) error {
	p.started.Store(true)
	p.activeWorkers.Add(1)
	p.signalChanged()
	defer func() {
		p.activeWorkers.Add(-1)
		p.exitedWorkers.Add(1)
		p.signalChanged()
	}()
	for {
		if !p.lifecycle.IsRunning() {
			p.drainQueued()
			return nil
		}
		select {
		case <-ctx.Done():
			p.drainQueued()
			return nil
		case <-p.lifecycle.Closing():
			p.drainQueued()
			return nil
		case work := <-p.queue:
			if work != nil {
				p.decide(ctx, work)
			}
		}
	}
}

// Handle transfers reader ownership into the bounded queue. Every overload
// branch resolves the current owner immediately.
func (p *DecisionPipeline) Handle(_ context.Context, pending PendingEvent) error {
	if pending == nil || pending.Event() == nil {
		return ErrPendingEventNotOwner
	}
	if !p.started.Load() || !p.lifecycle.IsRunning() {
		return pending.Respond(VerdictDeny)
	}

	var result error
	var denyOwner PendingEvent
	admitted := p.lifecycle.whileRunning(func() {
		for {
			outstanding := p.outstanding.Load()
			if outstanding >= p.config.OutstandingLimit {
				p.limitDenied.Add(1)
				denyOwner = pending
				return
			}
			if p.outstanding.CompareAndSwap(outstanding, outstanding+1) {
				break
			}
		}

		owner, err := pending.Transfer()
		if err != nil {
			p.outstanding.Add(-1)
			result = fmt.Errorf("transfer event to decision queue: %w", err)
			return
		}
		select {
		case p.queue <- &decisionWork{pending: owner}:
			p.recordQueueDepth()
			p.signalChanged()
		default:
			p.outstanding.Add(-1)
			p.queueDenied.Add(1)
			denyOwner = owner
		}
	})
	if !admitted {
		return pending.Respond(VerdictDeny)
	}
	if denyOwner != nil {
		return denyOwner.Respond(VerdictDeny)
	}
	return result
}

func (p *DecisionPipeline) decide(ctx context.Context, work *decisionWork) {
	p.activeMu.Lock()
	p.active[work] = struct{}{}
	p.activeMu.Unlock()
	p.activeDecisions.Add(1)
	p.signalChanged()

	releaseOutstanding := true
	completed := false
	defer func() {
		p.activeMu.Lock()
		delete(p.active, work)
		p.activeMu.Unlock()
		p.activeDecisions.Add(-1)
		if releaseOutstanding {
			p.outstanding.Add(-1)
		}
		p.signalChanged()
	}()

	pending := work.pending
	event := pending.Event()
	if event == nil || !p.lifecycle.IsRunning() {
		_ = resolvePendingCurrent(pending, VerdictDeny)
		return
	}

	verdict := VerdictDeny
	var afterResponse func()
	func() {
		defer func() {
			if recover() != nil {
				verdict = VerdictDeny
				afterResponse = nil
			}
		}()
		if handler, ok := p.handler.(pendingDecisionHandler); ok {
			var handled, handedOff, decided bool
			handled, handedOff, decided, verdict, afterResponse = handler.DecidePending(ctx, pending)
			if handled {
				completed = true
				if handedOff {
					releaseOutstanding = false
				}
				return
			}
			if decided {
				// DecidePending resolved a definitive verdict synchronously;
				// respond with it directly rather than repeating the full
				// process/profile lookup via DecideForResponse.
				return
			}
		}
		if handler, ok := p.handler.(postResponseDecisionHandler); ok {
			verdict, afterResponse = handler.DecideForResponse(ctx, event)
			return
		}
		verdict = p.handler.Decide(ctx, event)
	}()
	if completed || !releaseOutstanding {
		return
	}
	if ctx.Err() != nil || !p.lifecycle.IsRunning() {
		verdict = VerdictDeny
		afterResponse = nil
	}

	accepted := false
	if owner, ok := pending.(*pendingEventOwner); ok {
		accepted, _ = owner.respondAttempt(verdict)
	} else {
		accepted = pending.Respond(verdict) == nil
	}
	if !accepted || !p.lifecycle.IsRunning() {
		return
	}
	if verdict == VerdictAllow && event.Op == OpExec {
		if handler, ok := p.handler.(processMappingRefresher); ok {
			_ = handler.RefreshProcessMapping(ctx, event.PID)
		}
	}
	if afterResponse != nil {
		afterResponse()
	}
	if p.observe != nil {
		p.observe(event, verdict)
	}
}

func (p *DecisionPipeline) finishPromptEvent(ctx context.Context, pending PendingEvent, verdict Verdict) bool {
	defer p.releaseOutstanding()
	return p.finishTransferredPromptEvent(ctx, pending, verdict)
}

func (p *DecisionPipeline) finishTransferredPromptEvent(ctx context.Context, pending PendingEvent, verdict Verdict) bool {
	var event FileEvent
	hasEvent := false
	if source := pending.Event(); source != nil {
		event = *source
		hasEvent = true
	}
	accepted := false
	if owner, ok := pending.(*pendingEventOwner); ok {
		accepted, _ = owner.respondAttempt(verdict)
	} else {
		accepted = pending.Respond(verdict) == nil
	}
	if accepted && hasEvent && p.lifecycle.IsRunning() {
		if verdict == VerdictAllow && event.Op == OpExec {
			func() {
				defer func() { _ = recover() }()
				if handler, ok := p.handler.(processMappingRefresher); ok {
					_ = handler.RefreshProcessMapping(ctx, event.PID)
				}
			}()
		}
		if p.observe != nil {
			func() {
				defer func() { _ = recover() }()
				p.observe(&event, verdict)
			}()
		}
	}
	return accepted
}

func (p *DecisionPipeline) releaseOutstanding() {
	p.outstanding.Add(-1)
	p.signalChanged()
}

func (p *DecisionPipeline) acquireAsk(profileKey string) (func(), bool) {
	var release func()
	admitted := p.lifecycle.whileRunning(func() {
		if profileKey == "" {
			release = func() {}
			return
		}
		p.askMu.Lock()
		if p.pendingAsk[profileKey] >= p.config.PerProfileAskLimit {
			p.askMu.Unlock()
			p.askDenied.Add(1)
			return
		}
		p.pendingAsk[profileKey]++
		p.askMu.Unlock()

		var once sync.Once
		release = func() {
			once.Do(func() {
				p.askMu.Lock()
				p.pendingAsk[profileKey]--
				if p.pendingAsk[profileKey] == 0 {
					delete(p.pendingAsk, profileKey)
				}
				p.askMu.Unlock()
				p.signalChanged()
			})
		}
	})
	if !admitted || release == nil {
		return nil, false
	}
	return release, true
}

func (p *DecisionPipeline) signalChanged() {
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func (p *DecisionPipeline) drainQueued() {
	for {
		select {
		case work := <-p.queue:
			if work == nil {
				continue
			}
			_ = resolvePendingCurrent(work.pending, VerdictDeny)
			p.outstanding.Add(-1)
			p.signalChanged()
		default:
			return
		}
	}
}

func (p *DecisionPipeline) resolveActiveForShutdown() {
	p.activeMu.Lock()
	active := make([]*decisionWork, 0, len(p.active))
	for work := range p.active {
		active = append(active, work)
	}
	p.activeMu.Unlock()
	for _, work := range active {
		// Only resolve ownership still held by this active worker. Transferred
		// ownership belongs to the prompt coordinator and is drained there.
		_ = work.pending.Respond(VerdictDeny)
	}
}

func (p *DecisionPipeline) Drain(ctx context.Context) error {
	for {
		p.drainQueued()
		p.resolveActiveForShutdown()
		if len(p.queue) == 0 && p.activeDecisions.Load() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.changed:
		}
	}
}

func (p *DecisionPipeline) WaitOutstanding(ctx context.Context) error {
	for {
		if p.outstanding.Load() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.changed:
		}
	}
}

// WaitWorkers joins every configured decision worker. The expected count is
// registered before launch so not-yet-scheduled workers cannot be mistaken for
// workers that have already exited.
func (p *DecisionPipeline) WaitWorkers(ctx context.Context) error {
	for {
		expected := p.expectedWorkers.Load()
		if p.activeWorkers.Load() == 0 && p.exitedWorkers.Load() >= expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.changed:
		}
	}
}

func (p *DecisionPipeline) recordQueueDepth() {
	depth := int64(len(p.queue))
	for {
		peak := p.peakQueue.Load()
		if depth <= peak || p.peakQueue.CompareAndSwap(peak, depth) {
			return
		}
	}
}

func (p *DecisionPipeline) Diagnostics() DecisionPipelineDiagnostics {
	p.askMu.Lock()
	pendingAsk := 0
	var pendingAskByProfile map[string]int
	if len(p.pendingAsk) > 0 {
		pendingAskByProfile = make(map[string]int, len(p.pendingAsk))
	}
	for profileKey, count := range p.pendingAsk {
		pendingAsk += count
		pendingAskByProfile[profileKey] = count
	}
	p.askMu.Unlock()
	return DecisionPipelineDiagnostics{
		QueueDepth:              len(p.queue),
		PeakQueueDepth:          p.peakQueue.Load(),
		Workers:                 p.config.Workers,
		ActiveWorkers:           p.activeWorkers.Load(),
		ExpectedWorkers:         p.expectedWorkers.Load(),
		ExitedWorkers:           p.exitedWorkers.Load(),
		ActiveDecisions:         p.activeDecisions.Load(),
		Outstanding:             p.outstanding.Load(),
		PendingAsk:              pendingAsk,
		PendingAskByProfile:     pendingAskByProfile,
		Closing:                 !p.lifecycle.IsRunning(),
		QueueSaturationDenies:   p.queueDenied.Load(),
		OutstandingBudgetDenies: p.limitDenied.Load(),
		ProfileAskBudgetDenies:  p.askDenied.Load(),
	}
}
