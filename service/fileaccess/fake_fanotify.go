package fileaccess

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	envFileAccessSource     = "FM_FILEACCESS_SOURCE"
	envFakeFanotifyEvents   = "FM_FAKE_FANOTIFY_EVENTS"
	fakeFanotifySourceValue = "fake"
)

type fakeFanotifySource struct {
	log    logger
	closed chan struct{}
	once   sync.Once

	mu     sync.Mutex
	paths  []string
	events []fakeFanotifyEvent
}

type fakeFanotifyEvent struct {
	Delay             string `json:"Delay"`
	PID               int32  `json:"PID"`
	Exe               string `json:"Exe"`
	Path              string `json:"Path"`
	Op                string `json:"Op"`
	ProfileID         string `json:"ProfileID"`
	ProfileSource     string `json:"ProfileSource"`
	ProfileName       string `json:"ProfileName"`
	ProfileLinkedPath string `json:"ProfileLinkedPath"`
}

func (e *fakeFanotifyEvent) UnmarshalJSON(data []byte) error {
	type flatEvent fakeFanotifyEvent
	var raw struct {
		flatEvent
		Profile FilePromptProfile `json:"Profile"`
		Subject FilePromptSubject `json:"Subject"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*e = fakeFanotifyEvent(raw.flatEvent)
	if raw.Subject.PID != 0 {
		e.PID = raw.Subject.PID
	}
	if raw.Subject.Exe != "" {
		e.Exe = raw.Subject.Exe
	}
	if raw.Subject.Path != "" {
		e.Path = raw.Subject.Path
	}
	if raw.Subject.Op != "" {
		e.Op = raw.Subject.Op
	}
	if raw.Profile.ID != "" {
		e.ProfileID = raw.Profile.ID
	}
	if raw.Profile.Source != "" {
		e.ProfileSource = raw.Profile.Source
	}
	if raw.Profile.Name != "" {
		e.ProfileName = raw.Profile.Name
	}
	if raw.Profile.LinkedPath != "" {
		e.ProfileLinkedPath = raw.Profile.LinkedPath
	}
	return nil
}

func fakeFanotifyFromEnv(log logger) (Source, bool, error) {
	if strings.ToLower(strings.TrimSpace(os.Getenv(envFileAccessSource))) != fakeFanotifySourceValue {
		return nil, false, nil
	}
	events, err := fakeFanotifyEventsFromEnv()
	if err != nil {
		return nil, true, err
	}
	return &fakeFanotifySource{
		log:    log,
		closed: make(chan struct{}),
		paths:  resolveWatchPaths(),
		events: events,
	}, true, nil
}

func fakeFanotifyEventsFromEnv() ([]fakeFanotifyEvent, error) {
	path := strings.TrimSpace(os.Getenv(envFakeFanotifyEvents))
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fake fanotify events: %w", err)
	}
	defer func() { _ = f.Close() }()

	var events []fakeFanotifyEvent
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var event fakeFanotifyEvent
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return nil, fmt.Errorf("parse fake fanotify event line %d: %w", line, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read fake fanotify events: %w", err)
	}
	return events, nil
}

func (s *fakeFanotifySource) Run(ctx context.Context, h Handler) error {
	events := s.snapshotEvents()
	s.log.Info("fake fanotify source started", "events", len(events))
	for _, fakeEvent := range events {
		if fakeEvent.Delay != "" {
			delay, err := time.ParseDuration(fakeEvent.Delay)
			if err != nil {
				return fmt.Errorf("parse fake fanotify delay %q: %w", fakeEvent.Delay, err)
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-s.closed:
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-s.closed:
			return nil
		default:
		}
		event := fakeEvent.fileEvent()
		verdict := h.Decide(ctx, event)
		s.log.Info("fanotify event",
			"pid", event.PID,
			"path", event.Path,
			"op", event.Op,
			"perm", true,
			"verdict", verdict,
		)
	}
	select {
	case <-ctx.Done():
	case <-s.closed:
	}
	return nil
}

func (s *fakeFanotifySource) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *fakeFanotifySource) SetWatchPaths(paths []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append([]string(nil), paths...)
	return nil
}

func (s *fakeFanotifySource) snapshotEvents() []fakeFanotifyEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) > 0 {
		return append([]fakeFanotifyEvent(nil), s.events...)
	}
	paths := append([]string(nil), s.paths...)
	if len(paths) == 0 {
		paths = []string{defaultWatchPath}
	}
	root := strings.TrimSpace(paths[0])
	if root == "" {
		root = defaultWatchPath
	}
	return []fakeFanotifyEvent{
		{Delay: "250ms", PID: int32(os.Getpid() + 1), Path: filepath.Join(root, "ui-demo-open.txt"), Op: "open"},
		{Delay: "750ms", PID: int32(os.Getpid() + 2), Path: filepath.Join(root, "ui-demo-read.txt"), Op: "read"},
		{Delay: "1250ms", PID: int32(os.Getpid() + 3), Path: filepath.Join(root, "ui-demo-exec.py"), Op: "exec"},
	}
}

func (e fakeFanotifyEvent) fileEvent() FileEvent {
	return FileEvent{
		PID:               e.PID,
		Exe:               e.Exe,
		Path:              e.Path,
		Op:                fakeFanotifyOp(e.Op),
		ProfileID:         e.ProfileID,
		ProfileSource:     e.ProfileSource,
		ProfileName:       e.ProfileName,
		ProfileLinkedPath: e.ProfileLinkedPath,
	}
}

func fakeFanotifyOp(op string) FileOp {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "read":
		return OpRead
	case "exec", "execute":
		return OpExec
	default:
		return OpOpen
	}
}
