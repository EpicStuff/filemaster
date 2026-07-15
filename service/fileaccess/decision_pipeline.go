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
	Outstanding             int64
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

type decisionWork struct {
	pending PendingEvent
}

// DecisionPipeline is one bounded queue serviced by a fixed worker pool. The
// reader transfers ownership into the queue and never waits for profile lookup,
// prompting, persistence, or observation work.
type DecisionPipeline struct {
	config  DecisionPipelineConfig
	handler Handler
	observe func(*FileEvent, Verdict)
	queue   chan decisionWork

	started atomic.Bool

	outstanding atomic.Int64
	peakQueue   atomic.Int64
	queueDenied atomic.Uint64
	limitDenied atomic.Uint64
	askDenied   atomic.Uint64

	askMu      sync.Mutex
	pendingAsk map[string]int
}

func NewDecisionPipeline(handler Handler, config DecisionPipelineConfig) *DecisionPipeline {
	config = config.normalized()
	pipeline := &DecisionPipeline{
		config:     config,
		handler:    handler,
		queue:      make(chan decisionWork, config.QueueCapacity),
		pendingAsk: make(map[string]int),
	}
	if observer, ok := handler.(responseObserver); ok {
		pipeline.handler = observer.DecisionHandler()
		pipeline.observe = observer.Observe
	}
	if handler, ok := pipeline.handler.(*ProfileHandler); ok {
		handler.setPromptAdmission(pipeline.acquireAsk)
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
	p.started.Store(true)
}

func (p *DecisionPipeline) Start(ctx context.Context) {
	if !p.started.CompareAndSwap(false, true) {
		return
	}
	for range p.config.Workers {
		go p.Run(ctx)
	}
}

// Run services queue work in one fixed worker. It must be called exactly once
// per configured worker by production wiring.
func (p *DecisionPipeline) Run(ctx context.Context) error {
	p.started.Store(true)
	for {
		select {
		case <-ctx.Done():
			return nil
		case work := <-p.queue:
			p.decide(ctx, work.pending)
		}
	}
}

// Handle transfers reader ownership into the bounded queue. Every overload
// branch resolves the current owner immediately.
func (p *DecisionPipeline) Handle(_ context.Context, pending PendingEvent) error {
	if pending == nil || pending.Event() == nil {
		return ErrPendingEventNotOwner
	}
	if !p.started.Load() {
		return pending.Respond(VerdictDeny)
	}
	for {
		outstanding := p.outstanding.Load()
		if outstanding >= p.config.OutstandingLimit {
			p.limitDenied.Add(1)
			return pending.Respond(VerdictDeny)
		}
		if p.outstanding.CompareAndSwap(outstanding, outstanding+1) {
			break
		}
	}

	owner, err := pending.Transfer()
	if err != nil {
		p.outstanding.Add(-1)
		return fmt.Errorf("transfer event to decision queue: %w", err)
	}
	select {
	case p.queue <- decisionWork{pending: owner}:
		p.recordQueueDepth()
		return nil
	default:
		p.outstanding.Add(-1)
		p.queueDenied.Add(1)
		return owner.Respond(VerdictDeny)
	}
}

func (p *DecisionPipeline) decide(ctx context.Context, pending PendingEvent) {
	defer p.outstanding.Add(-1)
	event := pending.Event()
	if event == nil {
		_ = pending.Respond(VerdictDeny)
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
		if handler, ok := p.handler.(postResponseDecisionHandler); ok {
			verdict, afterResponse = handler.DecideForResponse(ctx, event)
			return
		}
		verdict = p.handler.Decide(ctx, event)
	}()
	if ctx.Err() != nil {
		verdict = VerdictDeny
		afterResponse = nil
	}

	err := pending.Respond(verdict)
	accepted := err == nil
	if owner, ok := pending.(*pendingEventOwner); ok {
		accepted = owner.responseAccepted()
	}
	if !accepted {
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

func (p *DecisionPipeline) acquireAsk(profileKey string) (func(), bool) {
	if profileKey == "" {
		return func() {}, true
	}
	p.askMu.Lock()
	if p.pendingAsk[profileKey] >= p.config.PerProfileAskLimit {
		p.askMu.Unlock()
		p.askDenied.Add(1)
		return nil, false
	}
	p.pendingAsk[profileKey]++
	p.askMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			p.askMu.Lock()
			p.pendingAsk[profileKey]--
			if p.pendingAsk[profileKey] == 0 {
				delete(p.pendingAsk, profileKey)
			}
			p.askMu.Unlock()
		})
	}, true
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
	return DecisionPipelineDiagnostics{
		QueueDepth:              len(p.queue),
		PeakQueueDepth:          p.peakQueue.Load(),
		Workers:                 p.config.Workers,
		Outstanding:             p.outstanding.Load(),
		QueueSaturationDenies:   p.queueDenied.Load(),
		OutstandingBudgetDenies: p.limitDenied.Load(),
		ProfileAskBudgetDenies:  p.askDenied.Load(),
	}
}
