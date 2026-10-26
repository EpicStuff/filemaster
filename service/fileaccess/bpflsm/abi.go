//go:build linux

package bpflsm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// Byte layouts of bpf/filemaster-lsm-common's decision ABI. The committed
// Rust manifest test guards these constants against layout drift.
const (
	numBanks      = 2
	maxObjects    = 1024
	maxContexts   = 1024
	maxPatterns   = 1024
	maxChunks     = 8192
	maxTokens     = 32768
	maxRanges     = 16384
	contextRules  = 256
	contextScopes = 32
	arenaSize     = 1 << 20
	maxString     = 4095
	auditSlots    = 5
	hookCount     = 5
	reasonCount   = 11

	maxLabels       = 16384
	maxPolicies     = 1024
	maxRuleLists    = 2048
	maxPolicyLists  = 65536
	maxProcs        = 65536
	maxExecLabels   = 65536
	execScratchSize = 4096
	recordsSize     = 8 << 20
	recordBufSize   = 32768
	argsMax         = 8191
	envMax          = 16383
	labelCounters   = 9
	nomatchEntries  = numBanks * maxPolicies * 10

	labelUnidentified = 0
	labelPending      = 0xFFFFFFFF
	policyPending     = 0

	settingsLabelling = 1
	settingsBtrfs     = 2
	ruleListOverflow  = 1

	recordExec          = 1
	recordFork          = 2
	recordDecision      = 3
	recordArgsTruncated = 1
	recordEnvTruncated  = 2

	settingsSize            = 40
	waitSettingsSize        = 16
	objectKeySize           = 32
	objectKeyBank           = 24
	objectValueSize         = 8
	scopeRefSize            = 12
	ruleRefSize             = 4
	contextSize             = 24 + contextScopes*scopeRefSize
	ruleListSize            = 8 + contextRules*ruleRefSize
	policyListKey           = 12
	execFileSize            = 24
	execLabelKey            = 2 * execFileSize
	procValueSize           = 24
	resolvedSize            = 24
	recordHeader            = 104
	decisionRecordSize      = 16496
	decisionPathMax         = 8192
	decisionSuppressEntries = 4096
	decisionSuppressLimit   = 64
	patternSize             = 20
	chunkSize               = 12
	tokenSize               = 12
	rangeSize               = 8
	arenaValueSize          = arenaSize + 4096
	scratchSize             = 16384 + 4096
	stateSlots              = 8
	offsetsSize             = 116

	contextOverflow  = 1
	contextSubvolume = 2
	ruleAllow        = 1
	ruleKindShift    = 1

	tokenLiteral  = 0
	tokenQuestion = 1
	tokenClass    = 2
)

var policyMaps = []string{
	"SETTINGS", "OBJECTS", "CONTEXTS", "PATTERNS", "CHUNKS", "TOKENS", "RANGES", "ARENA", "NOMATCH", "AUDIT", "COUNTERS",
	"POLICY_LISTS", "RULELISTS", "LABEL_POLICY", "PROCS", "RESOLVED", "EXEC_LABELS", "LABEL_COUNTERS", "WAIT",
	"WAITERS",
}

func checkMapLayout(spec *ebpf.CollectionSpec) error {
	for name, want := range map[string][3]uint32{
		"SETTINGS": {4, settingsSize, 1},
		"OBJECTS":  {objectKeySize, objectValueSize, numBanks * maxObjects},
		"CONTEXTS": {4, contextSize, numBanks * maxContexts},
		"PATTERNS": {4, patternSize, numBanks * maxPatterns},
		"CHUNKS":   {4, chunkSize, numBanks * maxChunks},
		"TOKENS":   {4, tokenSize, numBanks * maxTokens},
		"RANGES":   {4, rangeSize, numBanks * maxRanges},
		"ARENA":    {4, arenaValueSize, numBanks},
		"NOMATCH":  {4, 4, nomatchEntries},
		"AUDIT":    {4, 8, auditSlots},
		"COUNTERS": {4, 8, hookCount * reasonCount},
		"SCRATCH":  {4, scratchSize, 2 * stateSlots},

		"STATE_CLAIMS": {4, 8, stateSlots},

		"POLICY_LISTS":      {policyListKey, 4, maxPolicyLists},
		"RULELISTS":         {4, ruleListSize, numBanks * maxRuleLists},
		"LABEL_POLICY":      {4, 4, numBanks * maxLabels},
		"PROCS":             {4, procValueSize, maxProcs},
		"RESOLVED":          {4, resolvedSize, maxProcs},
		"EXEC_LABELS":       {execLabelKey, 4, maxExecLabels},
		"EXEC_SCRATCH":      {8, execFileSize, execScratchSize},
		"RECORDS":           {0, 0, recordsSize},
		"RECORD_BUF":        {4, recordBufSize, 2},
		"DECISION_SUPPRESS": {12, 24, decisionSuppressEntries},
		"DECISION_DROPS":    {4, 8, 1},
		"LABEL_COUNTERS":    {4, 8, labelCounters},
		"WAIT":              {4, waitSettingsSize, 1},
		"WAITERS":           {4, 8, 1},
	} {
		m, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("object has no %s map", name)
		}
		if m.KeySize != want[0] || m.ValueSize != want[1] || m.MaxEntries != want[2] {
			return fmt.Errorf("%s map is key=%d value=%d entries=%d, loader expects key=%d value=%d entries=%d",
				name, m.KeySize, m.ValueSize, m.MaxEntries, want[0], want[1], want[2])
		}
	}
	return nil
}

// fileID is the kernel's inode identity: sb->s_dev in the kernel's internal
// encoding (major<<20 | minor), the inode number, and for objects the btrfs
// subvolume (0 elsewhere).
type fileID struct {
	dev    uint64
	ino    uint64
	subvol uint64
}

// pathStat is the statx subset objects are keyed by. hasSubvol reports that
// the filesystem filled STATX_SUBVOL.
type pathStat struct {
	ino       uint64
	mountID   uint64
	subvol    uint64
	hasSubvol bool
	mode      uint16
}

func statPath(path string) (pathStat, error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_NO_AUTOMOUNT, unix.STATX_INO|unix.STATX_MODE|unix.STATX_MNT_ID|unix.STATX_SUBVOL, &st); err != nil {
		return pathStat{}, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return pathStat{}, fmt.Errorf("statx %s: kernel reported no mount ID", path)
	}
	return pathStat{ino: st.Ino, mountID: st.Mnt_id, subvol: st.Subvol, hasSubvol: st.Mask&unix.STATX_SUBVOL != 0, mode: st.Mode}, nil
}

// pathFileID keys path by the superblock device of the mount that statx
// reports, from mountinfo, never stat's st_dev, which differs from sb->s_dev
// on btrfs subvolumes. It is an executable's identity, which has no subvolume.
func pathFileID(path string) (fileID, error) {
	st, err := statPath(path)
	if err != nil {
		return fileID{}, err
	}
	ino, mountID := st.ino, st.mountID
	mounts, err := mountinfo.GetMounts(func(info *mountinfo.Info) (skip, stop bool) {
		return uint64(info.ID) != mountID, uint64(info.ID) == mountID
	})
	if err != nil {
		return fileID{}, err
	}
	if len(mounts) == 0 {
		return fileID{}, fmt.Errorf("no mount %d for %s", mountID, path)
	}
	return fileID{dev: deviceID(mounts[0]), ino: ino}, nil
}

func deviceID(info *mountinfo.Info) uint64 {
	return uint64(info.Major)<<20 | uint64(info.Minor)
}

// Settings: daemon start@0, daemon tgid@8, start span@12, active bank@16,
// audit@20, flags@24, btrfs root@28, btrfs root id@32, padding@36.
func encodeSettings(s publishedSettings) []byte {
	b := make([]byte, settingsSize)
	binary.LittleEndian.PutUint64(b[0:], s.daemon.start)
	binary.LittleEndian.PutUint32(b[8:], s.daemon.tgid)
	binary.LittleEndian.PutUint32(b[12:], s.daemon.span)
	binary.LittleEndian.PutUint32(b[16:], s.bank)
	if s.audit {
		binary.LittleEndian.PutUint32(b[20:], 1)
	}
	var flags uint32
	if s.labelling {
		flags |= settingsLabelling
	}
	if s.btrfs.ok {
		flags |= settingsBtrfs
		binary.LittleEndian.PutUint32(b[28:], uint32(s.btrfs.root))
		binary.LittleEndian.PutUint32(b[32:], s.btrfs.rootID)
	}
	binary.LittleEndian.PutUint32(b[24:], flags)
	return b
}

// WaitSettings: heartbeat@0, max waiters@8, enabled@12.
func encodeWaitSettings(heartbeat uint64, maxWaiters uint32, enabled bool) []byte {
	b := make([]byte, waitSettingsSize)
	binary.LittleEndian.PutUint64(b[0:], heartbeat)
	binary.LittleEndian.PutUint32(b[8:], maxWaiters)
	if enabled {
		binary.LittleEndian.PutUint32(b[12:], 1)
	}
	return b
}

// ObjectKey: dev@0, ino@8, subvol@16, bank@24, explicit trailing padding@28.
func encodeObjectKey(bank uint32, id fileID) []byte {
	b := make([]byte, objectKeySize)
	binary.LittleEndian.PutUint64(b[0:], id.dev)
	binary.LittleEndian.PutUint64(b[8:], id.ino)
	binary.LittleEndian.PutUint64(b[16:], id.subvol)
	binary.LittleEndian.PutUint32(b[objectKeyBank:], bank)
	return b
}

// ObjectValue: first context@0, context count@4.
func encodeObjectValue(first, count uint32) []byte {
	b := make([]byte, objectValueSize)
	binary.LittleEndian.PutUint32(b[0:], first)
	binary.LittleEndian.PutUint32(b[4:], count)
	return b
}

// Context: path_off, path_len, parent_len, flags, scope_count, padding, then
// the ScopeRef (off, len, exclude) array.
func encodeContext(c CompiledContext, arena map[string]uint32) []byte {
	b := make([]byte, contextSize)
	pathLen := uint32(len(c.Path))
	if c.Path == "/" {
		pathLen = 0
	}
	binary.LittleEndian.PutUint32(b[0:], arena[c.Path])
	binary.LittleEndian.PutUint32(b[4:], pathLen)
	binary.LittleEndian.PutUint32(b[8:], c.ParentLen)
	if c.Subvolume {
		binary.LittleEndian.PutUint32(b[12:], contextSubvolume)
		return b
	}
	if c.Overflow {
		binary.LittleEndian.PutUint32(b[12:], contextOverflow)
		return b
	}
	binary.LittleEndian.PutUint32(b[16:], uint32(len(c.Scopes)))
	for i, scope := range c.Scopes {
		at := 24 + i*scopeRefSize
		binary.LittleEndian.PutUint32(b[at:], arena[scope.Path])
		binary.LittleEndian.PutUint32(b[at+4:], uint32(len(scope.Path)))
		if scope.Exclude {
			binary.LittleEndian.PutUint32(b[at+8:], 1)
		}
	}
	return b
}

// RuleList: rule_count, flags, then the RuleRef (pattern u16, list u8, flags
// u8) array.
func encodeRuleList(l CompiledRuleList) []byte {
	b := make([]byte, ruleListSize)
	if l.Overflow {
		binary.LittleEndian.PutUint32(b[4:], ruleListOverflow)
		return b
	}
	binary.LittleEndian.PutUint32(b[0:], uint32(len(l.Rules)))
	for i, rule := range l.Rules {
		at := 8 + i*ruleRefSize
		binary.LittleEndian.PutUint16(b[at:], rule.Pattern)
		b[at+2] = uint8(rule.List)
		flags := uint8(rule.Kind) << ruleKindShift
		if rule.Allow {
			flags |= ruleAllow
		}
		b[at+3] = flags
	}
	return b
}

func encodePolicyListKey(bank, policy, context uint32) []byte {
	b := make([]byte, policyListKey)
	binary.LittleEndian.PutUint32(b[0:], bank)
	binary.LittleEndian.PutUint32(b[4:], policy)
	binary.LittleEndian.PutUint32(b[8:], context)
	return b
}

// ExecFile: dev@0, ino@8, generation@16, padding@20.
func putExecFile(b []byte, f ExecFile) {
	binary.LittleEndian.PutUint64(b[0:], f.Dev)
	binary.LittleEndian.PutUint64(b[8:], f.Ino)
	binary.LittleEndian.PutUint32(b[16:], f.Generation)
}

func readExecFile(b []byte) ExecFile {
	return ExecFile{Dev: binary.LittleEndian.Uint64(b[0:]), Ino: binary.LittleEndian.Uint64(b[8:]), Generation: binary.LittleEndian.Uint32(b[16:])}
}

func encodeExecLabelKey(exe, script ExecFile) []byte {
	b := make([]byte, execLabelKey)
	putExecFile(b[0:], exe)
	putExecFile(b[execFileSize:], script)
	return b
}

// ProcValue: start@0, seq@8, span@16, label@20.
func encodeProcValue(v ProcValue) []byte {
	b := make([]byte, procValueSize)
	binary.LittleEndian.PutUint64(b[0:], v.Start)
	binary.LittleEndian.PutUint64(b[8:], v.Seq)
	binary.LittleEndian.PutUint32(b[16:], v.Span)
	binary.LittleEndian.PutUint32(b[20:], v.Label)
	return b
}

func decodeProcValue(b []byte) ProcValue {
	return ProcValue{
		Start: binary.LittleEndian.Uint64(b[0:]),
		Seq:   binary.LittleEndian.Uint64(b[8:]),
		Span:  binary.LittleEndian.Uint32(b[16:]),
		Label: binary.LittleEndian.Uint32(b[20:]),
	}
}

// Resolved: start@0, seq@8, label@16, padding@20.
func encodeResolved(start, seq uint64, label uint32) []byte {
	b := make([]byte, resolvedSize)
	binary.LittleEndian.PutUint64(b[0:], start)
	binary.LittleEndian.PutUint64(b[8:], seq)
	binary.LittleEndian.PutUint32(b[16:], label)
	return b
}

// decodeRecord parses one ring-buffer record: the RecordHeader, then argv and
// envp as NUL-separated strings.
func decodeRecord(b []byte) (Record, error) {
	if len(b) < 4 {
		return Record{}, fmt.Errorf("record of %d bytes has no kind", len(b))
	}
	if binary.LittleEndian.Uint32(b[0:]) == recordDecision {
		if len(b) < decisionRecordSize {
			return Record{}, fmt.Errorf("decision record of %d bytes is shorter than %d", len(b), decisionRecordSize)
		}
		sourceLen := int(binary.LittleEndian.Uint32(b[96:]))
		targetLen := int(binary.LittleEndian.Uint32(b[100:]))
		if sourceLen > decisionPathMax || targetLen > decisionPathMax {
			return Record{}, fmt.Errorf("decision path lengths %d and %d exceed %d", sourceLen, targetLen, decisionPathMax)
		}
		flags := binary.LittleEndian.Uint32(b[28:])
		decision := &DecisionRecord{
			Operation:     binary.LittleEndian.Uint32(b[4:]),
			Verdict:       binary.LittleEndian.Uint32(b[8:]),
			Reason:        binary.LittleEndian.Uint32(b[12:]),
			Label:         binary.LittleEndian.Uint32(b[20:]),
			Bank:          binary.LittleEndian.Uint32(b[24:]),
			SourceValid:   flags&1 != 0,
			TargetValid:   flags&2 != 0,
			Source:        decodeFileID(b[40:]),
			Target:        decodeFileID(b[64:]),
			SourceContext: binary.LittleEndian.Uint32(b[88:]),
			TargetContext: binary.LittleEndian.Uint32(b[92:]),
			SourcePath:    string(b[112 : 112+sourceLen]),
			TargetPath:    string(b[8304 : 8304+targetLen]),
			Suppressed:    binary.LittleEndian.Uint32(b[104:]),
		}
		return Record{Kind: recordDecision, TGID: binary.LittleEndian.Uint32(b[16:]), Start: binary.LittleEndian.Uint64(b[32:]), Decision: decision}, nil
	}
	if len(b) < recordHeader {
		return Record{}, fmt.Errorf("record of %d bytes is shorter than its %d-byte header", len(b), recordHeader)
	}
	r := Record{
		Kind:       binary.LittleEndian.Uint32(b[0:]),
		TGID:       binary.LittleEndian.Uint32(b[4:]),
		Start:      binary.LittleEndian.Uint64(b[8:]),
		Seq:        binary.LittleEndian.Uint64(b[16:]),
		Exe:        readExecFile(b[24:]),
		Script:     readExecFile(b[48:]),
		ParentSeq:  binary.LittleEndian.Uint64(b[72:]),
		ParentTGID: binary.LittleEndian.Uint32(b[80:]),
	}
	flags := binary.LittleEndian.Uint32(b[84:])
	r.ArgsTruncated = flags&recordArgsTruncated != 0
	r.EnvTruncated = flags&recordEnvTruncated != 0
	argsLen := int(binary.LittleEndian.Uint32(b[88:]))
	envLen := int(binary.LittleEndian.Uint32(b[92:]))
	pathLen := int(binary.LittleEndian.Uint32(b[96:]))
	if recordHeader+argsLen+envLen+pathLen > len(b) {
		return Record{}, fmt.Errorf("record strings (%d+%d+%d bytes) exceed its %d bytes", argsLen, envLen, pathLen, len(b))
	}
	r.Args = splitNUL(b[recordHeader : recordHeader+argsLen])
	r.Env = splitNUL(b[recordHeader+argsLen : recordHeader+argsLen+envLen])
	path := b[recordHeader+argsLen+envLen : recordHeader+argsLen+envLen+pathLen]
	r.Path = strings.TrimRight(string(path), "\x00")
	return r, nil
}

// ObjectId: dev@0, ino@8, subvol@16.
func decodeFileID(b []byte) fileID {
	return fileID{dev: binary.LittleEndian.Uint64(b[0:]), ino: binary.LittleEndian.Uint64(b[8:]), subvol: binary.LittleEndian.Uint64(b[16:])}
}

// splitNUL splits NUL-terminated strings; a truncated last string is kept.
func splitNUL(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
	return parts
}

// Pattern: off, len, recursive, chunk_off, chunk_len. A recursive pattern
// carries its /** prefix in the arena; a tokenized one carries a chunk range.
func encodePattern(p CompiledPattern, arena map[string]uint32) []byte {
	b := make([]byte, patternSize)
	if p.Recursive {
		binary.LittleEndian.PutUint32(b[0:], arena[p.Text])
		binary.LittleEndian.PutUint32(b[4:], uint32(len(p.Text)))
		binary.LittleEndian.PutUint32(b[8:], 1)
	} else {
		binary.LittleEndian.PutUint32(b[12:], p.ChunkOff)
		binary.LittleEndian.PutUint32(b[16:], p.ChunkLen)
	}
	return b
}

// Chunk: star, token_off, token_len.
func encodeChunk(c CompiledChunk) []byte {
	b := make([]byte, chunkSize)
	if c.Star {
		binary.LittleEndian.PutUint32(b[0:], 1)
	}
	binary.LittleEndian.PutUint32(b[4:], c.TokenOff)
	binary.LittleEndian.PutUint32(b[8:], c.TokenLen)
	return b
}

// Token: kind@0, byte@1, negated@2, pad@3, range_off@4, range_len@8.
func encodeToken(t CompiledToken) []byte {
	b := make([]byte, tokenSize)
	b[0] = byte(t.Kind)
	b[1] = t.Byte
	if t.Negated {
		b[2] = 1
	}
	binary.LittleEndian.PutUint32(b[4:], t.RangeOff)
	binary.LittleEndian.PutUint32(b[8:], t.RangeLen)
	return b
}

// Range: lo, hi.
func encodeRange(r CompiledRange) []byte {
	b := make([]byte, rangeSize)
	binary.LittleEndian.PutUint32(b[0:], r.Lo)
	binary.LittleEndian.PutUint32(b[4:], r.Hi)
	return b
}
