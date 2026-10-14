//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

const (
	defaultPinRoot     = "/sys/fs/bpf/filemaster"
	defaultSelfTestDir = "/run/filemaster/bpf-selftest"
	detachTimeout      = 5 * time.Second
)

// Mode is the fileaccess/structuralEnforcement setting.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeAudit   Mode = "audit"
	ModeEnforce Mode = "enforce"
)

// State is what the kernel side is actually doing.
type State string

const (
	StateOff         State = "off"
	StateUnavailable State = "unavailable"
	StateFailed      State = "failed"
	StateActive      State = "active"
)

// HookStatus reports one structural program's attachment.
type HookStatus struct {
	Program   string
	Operation string
	Attached  bool
	Error     string
}

// Status is a value-only snapshot for diagnostics.
type Status struct {
	Mode       Mode
	State      State
	Generation string
	Hooks      []HookStatus
	// Problems are probe failures that make BPF LSM unusable on this kernel.
	Problems []string
	Error    string
	// OrphanedGenerations are older pinned generations that could not be
	// removed, so their programs may still be enforcing.
	OrphanedGenerations []string
}

// Enforcer owns the loaded BPF LSM object and its pinned generations.
//
// Each start loads a fresh object, attaches it, self-tests it and pins it as a
// new generation under the pin root, then removes older generations. The old
// generation keeps enforcing until the new one is pinned, so a daemon restart
// leaves no unprotected gap, and pinned links survive the daemon being killed.
type Enforcer struct {
	mu          sync.Mutex
	pinRoot     string
	selfTestDir string
	collection  *ebpf.Collection
	links       []link.Link
	status      Status
}

// NewEnforcer returns an enforcer that has not attached anything.
func NewEnforcer() *Enforcer {
	return &Enforcer{
		pinRoot:     defaultPinRoot,
		selfTestDir: defaultSelfTestDir,
		status:      Status{Mode: ModeOff, State: StateOff},
	}
}

// Status returns a copy of the current status.
func (e *Enforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.status
	status.Hooks = slices.Clone(status.Hooks)
	status.Problems = slices.Clone(status.Problems)
	status.OrphanedGenerations = slices.Clone(status.OrphanedGenerations)
	return status
}

// SetMode attaches or detaches the structural hooks. Audit and enforce attach
// the same programs; the policy published to them decides what is denied.
func (e *Enforcer) SetMode(mode Mode) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if mode == ModeOff {
		e.release()
		orphans, err := teardown(e.pinRoot)
		e.status = Status{Mode: mode, State: StateOff, OrphanedGenerations: orphans}
		if err != nil {
			e.status.Error = err.Error()
		}
		return err
	}
	if e.collection != nil {
		e.status.Mode = mode
		return nil
	}
	e.status = e.start(mode)
	if e.status.State != StateActive {
		return errors.New(e.status.Error)
	}
	return nil
}

// Close releases this process's handles. Pinned generations stay attached,
// so enforcement with the last published policy outlives the daemon.
func (e *Enforcer) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.release()
}

func (e *Enforcer) release() {
	for _, l := range e.links {
		_ = l.Close()
	}
	e.links = nil
	if e.collection != nil {
		e.collection.Close()
		e.collection = nil
	}
}

func (e *Enforcer) start(mode Mode) Status {
	status := Status{Mode: mode, State: StateUnavailable}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		status.Problems = append(status.Problems, fmt.Sprintf("load kernel BTF: %v", err))
	}
	problems, missingHooks := probe(kernel)
	status.Problems = append(status.Problems, problems...)
	if len(status.Problems) > 0 {
		status.Error = "BPF LSM is unavailable: " + strings.Join(status.Problems, "; ")
		return status
	}

	status.State = StateFailed
	spec, err := loadSpec(Object(), kernel)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		status.Error = "load BPF LSM object: " + verifierError(err).Error()
		return status
	}
	// Bank 0 stays empty, so the new generation allows everything until a
	// policy is published.
	if err := collection.Maps["SETTINGS"].Put(uint32(0), encodeSettings(0, 0, fileID{})); err != nil {
		collection.Close()
		status.Error = fmt.Sprintf("seed settings: %v", err)
		return status
	}

	var links []link.Link
	attached := make(map[string]bool)
	for _, hook := range Hooks {
		hookStatus := HookStatus{Program: hook.Program, Operation: hook.Operation}
		if reason, missing := missingHooks[hook.Program]; missing {
			hookStatus.Error = reason
		} else if l, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[hook.Program]}); err != nil {
			hookStatus.Error = err.Error()
		} else {
			links = append(links, l)
			attached[hook.Program] = true
			hookStatus.Attached = true
		}
		status.Hooks = append(status.Hooks, hookStatus)
	}
	fail := func(format string, args ...any) Status {
		for _, l := range links {
			_ = l.Close()
		}
		collection.Close()
		for i := range status.Hooks {
			status.Hooks[i].Attached = false
		}
		status.Error = fmt.Sprintf(format, args...)
		return status
	}
	if len(links) == 0 {
		return fail("no BPF LSM hook attached")
	}
	if err := selfTest(collection, attached, e.selfTestDir); err != nil {
		return fail("BPF LSM self-test failed, so the new programs were detached: %v", err)
	}

	// The daemon's own structural operations bypass enforcement. The record
	// names the executable as well as the pid, because pinned links outlive
	// the daemon and its pid can be reused.
	exe, err := daemonFileID()
	if err != nil {
		return fail("identify daemon executable: %v", err)
	}
	if err := collection.Maps["SETTINGS"].Put(uint32(0), encodeSettings(uint32(os.Getpid()), 0, exe)); err != nil {
		return fail("publish settings: %v", err)
	}

	generation := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := pinGeneration(filepath.Join(e.pinRoot, generation), collection, links); err != nil {
		_ = os.RemoveAll(filepath.Join(e.pinRoot, generation))
		return fail("pin generation: %v", err)
	}
	status.Generation = generation
	status.OrphanedGenerations, err = sweep(e.pinRoot, generation)
	if err != nil {
		status.Error = err.Error()
	}
	status.State = StateActive
	e.collection = collection
	e.links = links
	return status
}

func pinGeneration(dir string, collection *ebpf.Collection, links []link.Link) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, l := range links {
		info, err := l.Info()
		if err != nil {
			return err
		}
		if err := l.Pin(filepath.Join(dir, "link-"+strconv.FormatUint(uint64(info.ID), 10))); err != nil {
			return err
		}
	}
	for _, name := range policyMaps {
		if err := collection.Maps[name].Pin(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// sweep removes every generation except keep and waits for their links to
// detach. It returns the generations it could not remove.
func sweep(root, keep string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var orphans []string
	var errs []error
	for _, entry := range entries {
		if entry.Name() == keep {
			continue
		}
		if err := removeGeneration(filepath.Join(root, entry.Name())); err != nil {
			orphans = append(orphans, entry.Name())
			errs = append(errs, err)
		}
	}
	return orphans, errors.Join(errs...)
}

// removeGeneration unpins one generation and detaches its links.
//
// Dropping a link's last reference by unlinking its pin defers the detach to
// a kernel workqueue, while its ID already reads as gone. Holding a descriptor
// across the unpin makes the final close ours, and closing a link descriptor
// detaches synchronously.
func removeGeneration(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var ids []link.ID
	var errs []error
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		var held link.Link
		if strings.HasPrefix(entry.Name(), "link-") {
			if l, err := link.LoadPinnedLink(path, nil); err == nil {
				if info, err := l.Info(); err == nil {
					ids = append(ids, info.ID)
				}
				held = l
			}
		}
		if err := os.Remove(path); err != nil {
			errs = append(errs, err)
		}
		if held != nil {
			_ = held.Close()
		}
	}
	if err := os.Remove(dir); err != nil {
		errs = append(errs, err)
	}
	if err := waitDetached(ids); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func waitDetached(ids []link.ID) error {
	deadline := time.Now().Add(detachTimeout)
	for {
		var remaining []link.ID
		for _, id := range ids {
			l, err := link.NewFromID(id)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err == nil {
				_ = l.Close()
			}
			remaining = append(remaining, id)
		}
		if len(remaining) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("BPF LSM links %v still attached after %s", remaining, detachTimeout)
		}
		ids = remaining
		time.Sleep(10 * time.Millisecond)
	}
}

// teardown removes every pinned generation and the pin root.
func teardown(root string) ([]string, error) {
	orphans, err := sweep(root, "")
	if err != nil {
		return orphans, err
	}
	if err := os.Remove(root); err != nil && !errors.Is(err, os.ErrNotExist) {
		return orphans, err
	}
	return nil, nil
}

// Teardown detaches and unpins every Filemaster BPF LSM generation. Package
// removal runs it, because pinned programs otherwise keep enforcing the last
// published policy after the daemon is gone.
func Teardown() error {
	_, err := teardown(defaultPinRoot)
	return err
}
