//go:build linux

package bpflsm

import (
	"encoding/binary"
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

// CompileWarning names rules the compiler left out of, or could not fit into,
// the kernel tables. Patterns are authored rule patterns, never user paths.
type CompileWarning struct {
	ID       string
	Patterns []string
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
	// WouldDeny is the per-operation total read from the per-CPU AUDIT map.
	WouldDeny map[string]uint64
	// Undecided counts, per reason and hook, the cases the kernel could not
	// decide exactly; only non-zero counts are listed.
	Undecided []UndecidedCount
	// CompileWarnings describe rules the compiler left out or could not fit.
	CompileWarnings []CompileWarning
}

// UndecidedCount is one non-zero COUNTERS total.
type UndecidedCount struct {
	Reason string
	Hook   string
	Count  uint64
}

// Undecided reasons, in COUNTERS order.
const (
	ReasonUnreadable       = "unreadable"
	ReasonDepth            = "depth-limit"
	ReasonPathTooLong      = "path-too-long"
	ReasonUnregisteredRoot = "unregistered-root"
	ReasonContextOverflow  = "context-overflow"
	ReasonBudget           = "evaluation-budget"
)

var undecidedReasons = [reasonCount]string{
	ReasonUnreadable, ReasonDepth, ReasonPathTooLong, ReasonUnregisteredRoot, ReasonContextOverflow, ReasonBudget,
}

// Enforcer owns the loaded BPF LSM object and its pinned generations.
//
// Each start loads a fresh object, attaches it, self-tests it and pins it as a
// new generation under the pin root, then removes older generations. The old
// generation keeps enforcing until the new one is pinned, so a daemon restart
// leaves no unprotected gap, and pinned links survive the daemon being killed.
type Enforcer struct {
	mu                sync.Mutex
	pinRoot           string
	selfTestDir       string
	daemonPIDOverride *uint32
	collection        *ebpf.Collection
	links             []link.Link
	status            Status
	settings          publishedSettings
	table             Table
}

type publishedSettings struct {
	daemonPID uint32
	bank      uint32
	exe       fileID
	audit     bool
}

// Options supplies non-default paths and identity only when an embedding
// caller needs them. Production uses NewEnforcer; the explicit identity is
// also what lets isolated kernel tests disable the daemon bypass.
type Options struct {
	PinRoot     string
	SelfTestDir string
	DaemonPID   *uint32
}

// NewEnforcer returns an enforcer that has not attached anything.
func NewEnforcer() *Enforcer {
	return NewEnforcerWithOptions(Options{})
}

// NewEnforcerWithOptions constructs an enforcer with optional isolated pin
// and self-test paths. Empty paths retain the production defaults.
func NewEnforcerWithOptions(options Options) *Enforcer {
	e := &Enforcer{
		pinRoot:     defaultPinRoot,
		selfTestDir: defaultSelfTestDir,
		status:      Status{Mode: ModeOff, State: StateOff},
	}
	if options.PinRoot != "" {
		e.pinRoot = options.PinRoot
	}
	if options.SelfTestDir != "" {
		e.selfTestDir = options.SelfTestDir
	}
	if options.DaemonPID != nil {
		pid := *options.DaemonPID
		e.daemonPIDOverride = &pid
	}
	return e
}

// Status returns a copy of the current status.
func (e *Enforcer) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := e.status
	status.Hooks = slices.Clone(status.Hooks)
	status.Problems = slices.Clone(status.Problems)
	status.OrphanedGenerations = slices.Clone(status.OrphanedGenerations)
	status.CompileWarnings = cloneCompileWarnings(status.CompileWarnings)
	if counters, err := auditCounters(e.collection); err == nil {
		status.WouldDeny = counters
	} else if e.collection != nil {
		status.Error = joinStatusError(status.Error, "read audit counters: "+err.Error())
	}
	if counters, err := undecidedCounts(e.collection); err == nil {
		status.Undecided = counters
	} else if e.collection != nil {
		status.Error = joinStatusError(status.Error, "read undecided counters: "+err.Error())
	}
	return status
}

// SetCompileWarnings publishes M2 table-coverage limitations to diagnostics.
func (e *Enforcer) SetCompileWarnings(warnings []CompileWarning) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.CompileWarnings = cloneCompileWarnings(warnings)
}

// SetPublishError records an error that occurred before a table could reach
// Publish, while leaving the previously active bank untouched.
func (e *Enforcer) SetPublishError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.status.Error = ""
		return
	}
	e.status.Error = "publish structural table: " + err.Error()
}

func cloneCompileWarnings(warnings []CompileWarning) []CompileWarning {
	cloned := make([]CompileWarning, len(warnings))
	for i, warning := range warnings {
		cloned[i] = CompileWarning{ID: warning.ID, Patterns: slices.Clone(warning.Patterns)}
	}
	return cloned
}

// SetMode attaches or detaches the structural hooks. Audit and enforce attach
// the same programs; an already active generation retains its current table
// when only the mode changes.
func (e *Enforcer) SetMode(mode Mode) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.setModeLocked(mode, e.table, false)
}

// SetModeWithTable starts a generation with table already active, or fills an
// inactive bank before changing the live mode. Starting this way is important:
// an older pinned generation is not swept until the replacement has a policy.
func (e *Enforcer) SetModeWithTable(mode Mode, table Table) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.setModeLocked(mode, table, true)
}

func (e *Enforcer) setModeLocked(mode Mode, table Table, replaceTable bool) error {
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
		if !replaceTable && e.status.Mode == mode {
			return nil
		}
		if !replaceTable {
			table = e.table
		}
		if err := e.publishLocked(table, mode); err != nil {
			e.status.Error = "publish structural mode: " + err.Error()
			return err
		}
		e.status.Mode = mode
		e.status.Error = ""
		return nil
	}
	e.status = e.start(mode, table)
	if e.status.State != StateActive {
		return errors.New(e.status.Error)
	}
	return nil
}

// Publish fills the inactive decision-table bank, then atomically flips
// SETTINGS.active_bank. On failure the old active bank remains in force.
func (e *Enforcer) Publish(table Table) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.collection == nil || e.status.State != StateActive {
		return errors.New("BPF LSM is not active")
	}
	if err := e.publishLocked(table, e.status.Mode); err != nil {
		e.status.Error = "publish structural table: " + err.Error()
		return err
	}
	e.status.Error = ""
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
	e.settings = publishedSettings{}
	e.table = Table{}
}

func (e *Enforcer) start(mode Mode, table Table) Status {
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
	// Bank 0 is deliberately empty during attachment and self-test. The caller's
	// table is published into bank 1 before this generation is pinned or any
	// older generation is swept.
	if err := collection.Maps["SETTINGS"].Put(uint32(0), encodeSettings(0, 0, fileID{}, mode == ModeAudit)); err != nil {
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
	settings := publishedSettings{
		daemonPID: uint32(os.Getpid()),
		bank:      0,
		exe:       exe,
		audit:     mode == ModeAudit,
	}
	if e.daemonPIDOverride != nil {
		settings.daemonPID = *e.daemonPIDOverride
	}
	if err := collection.Maps["SETTINGS"].Put(uint32(0), encodeSettings(settings.daemonPID, settings.bank, settings.exe, settings.audit)); err != nil {
		return fail("publish settings: %v", err)
	}
	e.collection = collection
	e.links = links
	e.settings = settings
	e.table = Table{}
	if err := e.publishLocked(table, mode); err != nil {
		e.collection = nil
		e.links = nil
		e.settings = publishedSettings{}
		e.table = Table{}
		return fail("publish initial structural table: %v", err)
	}

	generation := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := pinGeneration(filepath.Join(e.pinRoot, generation), collection, links); err != nil {
		_ = os.RemoveAll(filepath.Join(e.pinRoot, generation))
		e.collection = nil
		e.links = nil
		e.settings = publishedSettings{}
		e.table = Table{}
		return fail("pin generation: %v", err)
	}
	status.Generation = generation
	status.OrphanedGenerations, err = sweep(e.pinRoot, generation)
	if err != nil {
		status.Error = err.Error()
	}
	status.State = StateActive
	return status
}

func (e *Enforcer) publishLocked(table Table, mode Mode) error {
	inactive := e.settings.bank ^ 1
	if err := writeBank(e.collection.Maps, inactive, table); err != nil {
		return err
	}
	settings := e.settings
	settings.bank = inactive
	settings.audit = mode == ModeAudit
	if err := e.collection.Maps["SETTINGS"].Put(
		uint32(0),
		encodeSettings(settings.daemonPID, settings.bank, settings.exe, settings.audit),
	); err != nil {
		return fmt.Errorf("flip active decision-table bank: %w", err)
	}
	e.settings = settings
	e.table = table
	return nil
}

// writeBank replaces one bank's tables with table. The kernel reads only the
// active bank, so the inactive one can be rewritten in any order.
func writeBank(maps map[string]*ebpf.Map, bank uint32, table Table) error {
	if len(table.Objects) > maxObjects || len(table.Contexts) > maxContexts || len(table.Patterns) > maxPatterns ||
		len(table.Chunks) > maxChunks || len(table.Tokens) > maxTokens || len(table.Ranges) > maxRanges {
		return fmt.Errorf("table exceeds a bank limit: %d/%d objects, %d/%d contexts, %d/%d patterns, %d/%d chunks, %d/%d tokens, %d/%d ranges",
			len(table.Objects), maxObjects, len(table.Contexts), maxContexts, len(table.Patterns), maxPatterns,
			len(table.Chunks), maxChunks, len(table.Tokens), maxTokens, len(table.Ranges), maxRanges)
	}
	arena, offsets, err := layoutArena(table)
	if err != nil {
		return err
	}
	if err := clearObjectBank(maps["OBJECTS"], bank); err != nil {
		return fmt.Errorf("clear inactive OBJECTS bank: %w", err)
	}
	if err := maps["ARENA"].Put(bank, arena); err != nil {
		return fmt.Errorf("write ARENA: %w", err)
	}
	for i, pattern := range table.Patterns {
		if err := maps["PATTERNS"].Put(bank*maxPatterns+uint32(i), encodePattern(pattern, offsets)); err != nil {
			return fmt.Errorf("write PATTERNS[%d]: %w", i, err)
		}
	}
	for i, c := range table.Chunks {
		if err := maps["CHUNKS"].Put(bank*maxChunks+uint32(i), encodeChunk(c)); err != nil {
			return fmt.Errorf("write CHUNKS[%d]: %w", i, err)
		}
	}
	for i, t := range table.Tokens {
		if err := maps["TOKENS"].Put(bank*maxTokens+uint32(i), encodeToken(t)); err != nil {
			return fmt.Errorf("write TOKENS[%d]: %w", i, err)
		}
	}
	for i, r := range table.Ranges {
		if err := maps["RANGES"].Put(bank*maxRanges+uint32(i), encodeRange(r)); err != nil {
			return fmt.Errorf("write RANGES[%d]: %w", i, err)
		}
	}
	for i, context := range table.Contexts {
		if err := maps["CONTEXTS"].Put(bank*maxContexts+uint32(i), encodeContext(context, offsets)); err != nil {
			return fmt.Errorf("write CONTEXTS[%d]: %w", i, err)
		}
	}
	verdict := uint32(0)
	if table.DefaultAllow {
		verdict = 1
	}
	for index := bank * 10; index < bank*10+10; index++ {
		if err := maps["NOMATCH"].Put(index, verdict); err != nil {
			return fmt.Errorf("write NOMATCH[%d]: %w", index, err)
		}
	}
	for _, object := range table.Objects {
		if err := maps["OBJECTS"].Put(encodeObjectKey(bank, object.File), encodeObjectValue(object.FirstContext, object.ContextCount)); err != nil {
			return fmt.Errorf("write OBJECTS: %w", err)
		}
	}
	return nil
}

func clearObjectBank(m *ebpf.Map, bank uint32) error {
	var key [objectKeySize]byte
	var value [objectValueSize]byte
	var keys [][objectKeySize]byte
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if binary.LittleEndian.Uint32(key[16:]) == bank {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

func undecidedCounts(collection *ebpf.Collection) ([]UndecidedCount, error) {
	if collection == nil || collection.Maps["COUNTERS"] == nil {
		return nil, nil
	}
	var counts []UndecidedCount
	for reason := range reasonCount {
		for hook := range hookCount {
			values, err := perCPUValues()
			if err != nil {
				return nil, err
			}
			if err := collection.Maps["COUNTERS"].Lookup(uint32(reason*hookCount+hook), &values); err != nil {
				return nil, err
			}
			var total uint64
			for _, value := range values {
				total += value
			}
			if total > 0 {
				counts = append(counts, UndecidedCount{Reason: undecidedReasons[reason], Hook: Hooks[hook].Program, Count: total})
			}
		}
	}
	return counts, nil
}

func auditCounters(collection *ebpf.Collection) (map[string]uint64, error) {
	if collection == nil || collection.Maps["AUDIT"] == nil {
		return nil, nil
	}
	counters := make(map[string]uint64, len(allOperations))
	for _, operation := range allOperations {
		values, err := perCPUValues()
		if err != nil {
			return nil, err
		}
		if err := collection.Maps["AUDIT"].Lookup(uint32(operation), &values); err != nil {
			return nil, err
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		counters[operationName(operation)] = total
	}
	return counters, nil
}

// perCPUValues uses the map ABI's possible CPU count rather than online CPU
// count. Per-CPU maps require precisely this many values even when CPUs are
// offline.
func perCPUValues() ([]uint64, error) {
	count, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("read possible CPU count: %w", err)
	}
	return make([]uint64, count), nil
}

func operationName(operation Operation) string {
	switch operation {
	case OperationRead:
		return "read"
	case OperationWrite:
		return "write"
	case OperationExecute:
		return "execute"
	case OperationCreate:
		return "create"
	case OperationDelete:
		return "delete"
	default:
		return fmt.Sprintf("unknown-%d", operation)
	}
}

func joinStatusError(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
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
