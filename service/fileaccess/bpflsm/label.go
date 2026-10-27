//go:build linux

package bpflsm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// The kernel's labels for the unidentified profile and for a process the
// daemon has not resolved yet.
const (
	LabelUnidentified uint32 = labelUnidentified
	LabelPending      uint32 = labelPending
	// MaxLabels bounds the labels one daemon can assign.
	MaxLabels = maxLabels
)

// Record kinds.
const (
	RecordExec = recordExec
	RecordFork = recordFork
)

// clockTick is USER_HZ, the unit of /proc/<pid>/stat start times; it is 100
// on every architecture Filemaster builds for.
const clockTick = 10_000_000

// labelPrograms are the observe-only labelling programs, in attach order.
var labelPrograms = []string{"bprm_check_security", "bprm_committed_creds", "sched_process_fork", "sched_process_exec", "sched_process_exit"}

// ExecFile is an executable or script identity: superblock device, inode,
// inode generation and btrfs subvolume (0 on other filesystems, and
// execSubvolUnknown for a btrfs file the kernel read without the btrfs layout).
type ExecFile struct {
	Dev        uint64
	Ino        uint64
	Generation uint32
	Subvol     uint64
}

const execSubvolUnknown = ^uint64(0)

// ProcValue is the kernel's record of one thread group.
type ProcValue struct {
	Start uint64
	Seq   uint64
	Span  uint32
	Label uint32
}

// Record is one pending exec or fork the kernel asks the daemon to resolve.
// An exec carries the new image's argv and envp as read from its stack before
// any of its code ran; a fork names the pending parent it inherits from.
type Record struct {
	Kind       uint32
	TGID       uint32
	Start      uint64
	Seq        uint64
	Exe        ExecFile
	Script     ExecFile
	ParentTGID uint32
	ParentSeq  uint64
	Args       []string
	Env        []string
	// Path is the path the kernel loaded the final binary from, as the exec
	// named it; it can be relative and is unverified until SameFile checks it.
	Path          string
	ArgsTruncated bool
	EnvTruncated  bool
	Decision      *DecisionRecord
}

// SeededProcess is a process that predates the generation, entered as pending.
type SeededProcess struct {
	TGID  uint32
	Start uint64
}

// LabelStatus reports the labelling programs and their counters.
type LabelStatus struct {
	Enabled     bool
	Programs    []HookStatus
	MapFull     uint64
	RecordDrops uint64
	Unreadable  uint64
	Wait        LabelWait
	// ExeLearning is the daemon's exe-only label learning state, set by the
	// labeller: which executables are labelled by inode alone, or why none are.
	ExeLearning string
}

type daemonIdentity struct {
	tgid  uint32
	start uint64
	span  uint32
}

// procStart returns a process's start time from /proc/<pid>/stat, in
// nanoseconds of boot time truncated to a clock tick, and whether it is a
// kernel thread.
func procStart(pid int) (start uint64, kernelThread bool, err error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false, err
	}
	// The command name is parenthesized and may contain anything, so fields
	// are counted after its last ')'.
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, false, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[end+1:]))
	// fields[0] is field 3 (state); flags is field 9, starttime field 22.
	if len(fields) < 20 {
		return 0, false, fmt.Errorf("short /proc/%d/stat", pid)
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return 0, false, err
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false, err
	}
	const pfKthread = 0x00200000
	return ticks * clockTick, flags&pfKthread != 0, nil
}

func ownIdentity() (daemonIdentity, error) {
	pid := os.Getpid()
	start, _, err := procStart(pid)
	if err != nil {
		return daemonIdentity{}, fmt.Errorf("read own start time: %w", err)
	}
	return daemonIdentity{tgid: uint32(pid), start: start, span: clockTick - 1}, nil
}

func attachLabelling(collection *ebpf.Collection) ([]link.Link, []HookStatus, error) {
	var links []link.Link
	var statuses []HookStatus
	var errs []error
	for _, name := range labelPrograms {
		status := HookStatus{Program: name, Operation: "process labelling"}
		program := collection.Programs[name]
		var l link.Link
		var err error
		if program == nil {
			err = fmt.Errorf("object has no %s program", name)
		} else if program.Type() == ebpf.LSM {
			l, err = attachLSM(link.LSMOptions{Program: program})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: program})
		}
		if err != nil {
			status.Error = err.Error()
			errs = append(errs, fmt.Errorf("attach %s: %w", name, err))
		} else {
			status.Attached = true
			links = append(links, l)
		}
		statuses = append(statuses, status)
	}
	return links, statuses, errors.Join(errs...)
}

// SameFile reports whether path names the file a record identified, by
// superblock device, inode and, where the kernel read one, btrfs subvolume.
func SameFile(path string, file ExecFile) bool {
	id, err := pathFileID(path)
	if err != nil || id.dev != file.Dev || id.ino != file.Ino {
		return false
	}
	if file.Subvol == 0 || file.Subvol == execSubvolUnknown {
		return true
	}
	st, err := statPath(path)
	return err == nil && st.hasSubvol && st.subvol == file.Subvol
}

// labelMap returns one of the active generation's maps.
func (e *Enforcer) labelMap(name string) (*ebpf.Map, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.collection == nil || !e.settings.labelling {
		return nil, errors.New("BPF LSM labelling is not active")
	}
	m := e.collection.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("object has no %s map", name)
	}
	return m, nil
}

// Resolve answers one pending record: the kernel uses label for tgid only
// while its record still has this start time and sequence.
func (e *Enforcer) Resolve(tgid uint32, start, seq uint64, label uint32) error {
	m, err := e.labelMap("RESOLVED")
	if err != nil {
		return err
	}
	return m.Put(tgid, encodeResolved(start, seq, label))
}

// Proc returns the kernel's record of tgid.
func (e *Enforcer) Proc(tgid uint32) (ProcValue, bool, error) {
	m, err := e.labelMap("PROCS")
	if err != nil {
		return ProcValue{}, false, err
	}
	value := make([]byte, procValueSize)
	if err := m.Lookup(tgid, value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return ProcValue{}, false, nil
		}
		return ProcValue{}, false, err
	}
	return decodeProcValue(value), true, nil
}

// LearnExec labels future execs of exe (script zero) or of script run
// through interpreter exe, without a round trip to the daemon.
func (e *Enforcer) LearnExec(exe, script ExecFile, label uint32) error {
	m, err := e.labelMap("EXEC_LABELS")
	if err != nil {
		return err
	}
	return m.Put(encodeExecLabelKey(exe, script), label)
}

// ClearExecLabels forgets every learned exec label.
func (e *Enforcer) ClearExecLabels() error {
	m, err := e.labelMap("EXEC_LABELS")
	if err != nil {
		return err
	}
	var keys [][]byte
	key := make([]byte, execLabelKey)
	value := make([]byte, 4)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, bytes.Clone(key))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// SeedProcesses enters every user process that has no kernel record yet as
// pending, keyed by its /proc start time. Labelling must already be on, so a
// process forked or exec'd after the walk has its own record.
func (e *Enforcer) SeedProcesses() ([]SeededProcess, error) {
	m, err := e.labelMap("PROCS")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	self := os.Getpid()
	var seeded []SeededProcess
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		start, kernelThread, err := procStart(pid)
		if err != nil || kernelThread {
			continue
		}
		value := encodeProcValue(ProcValue{Start: start, Span: clockTick - 1, Label: labelPending})
		if err := m.Update(uint32(pid), value, ebpf.UpdateNoExist); err != nil {
			if errors.Is(err, ebpf.ErrKeyExist) {
				continue
			}
			return seeded, fmt.Errorf("seed process %d: %w", pid, err)
		}
		seeded = append(seeded, SeededProcess{TGID: uint32(pid), Start: start})
	}
	return seeded, nil
}

// readRecords delivers ring-buffer records until the reader is closed.
func readRecords(reader *ringbuf.Reader, handle func(Record), done chan<- struct{}) {
	defer close(done)
	for {
		raw, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		record, err := decodeRecord(raw.RawSample)
		if err != nil {
			continue
		}
		handle(record)
	}
}

func labelCounterTotals(collection *ebpf.Collection) (full, drops, unreadable uint64, err error) {
	if collection == nil || collection.Maps["LABEL_COUNTERS"] == nil {
		return 0, 0, 0, nil
	}
	var totals [labelCounters]uint64
	for index := range labelCounters {
		values, err := perCPUValues()
		if err != nil {
			return 0, 0, 0, err
		}
		if err := collection.Maps["LABEL_COUNTERS"].Lookup(uint32(index), &values); err != nil {
			return 0, 0, 0, err
		}
		for _, value := range values {
			totals[index] += value
		}
	}
	return totals[0], totals[1], totals[2], nil
}
