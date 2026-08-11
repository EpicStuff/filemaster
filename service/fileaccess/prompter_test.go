package fileaccess

import (
	"context"
	"sync"
	"time"
)

type scriptedPrompter struct {
	responses map[string]string
	noReply   map[string]bool

	mu     sync.Mutex
	called int
}

func (p *scriptedPrompter) Prompt(_ context.Context, event FileEvent, _ time.Duration) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.called++
	if p.noReply[event.Path] {
		return "", false
	}
	action, ok := p.responses[event.Path]
	return action, ok
}
