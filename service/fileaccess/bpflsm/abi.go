//go:build linux

package bpflsm

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

// Byte layouts of bpf/filemaster-lsm-common's decision ABI. The committed
// Rust manifest test guards these constants against layout drift.
const (
	numBanks       = 2
	maxObjects     = 1024
	maxContexts    = 1024
	maxPatterns    = 1024
	maxChunks      = 8192
	maxTokens      = 32768
	maxRanges      = 16384
	contextRules   = 256
	contextScopes  = 32
	arenaSize      = 1 << 20
	maxString      = 4095
	auditSlots     = 5
	nomatchEntries = numBanks * 5 * 2
	hookCount      = 5
	reasonCount    = 6

	settingsSize    = 32
	objectKeySize   = 24
	objectValueSize = 8
	scopeRefSize    = 12
	ruleRefSize     = 4
	contextSize     = 24 + contextScopes*scopeRefSize + contextRules*ruleRefSize
	patternSize     = 20
	chunkSize       = 12
	tokenSize       = 12
	rangeSize       = 8
	arenaValueSize  = arenaSize + 4096
	scratchSize     = 16384 + 4096
	offsetsSize     = 64

	contextOverflow = 1
	ruleAllow       = 1
	ruleKindShift   = 1

	tokenLiteral  = 0
	tokenQuestion = 1
	tokenClass    = 2
)

var policyMaps = []string{"SETTINGS", "OBJECTS", "CONTEXTS", "PATTERNS", "CHUNKS", "TOKENS", "RANGES", "ARENA", "NOMATCH", "AUDIT", "COUNTERS"}

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
		"SCRATCH":  {4, scratchSize, 2},
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
// encoding (major<<20 | minor) and the inode number.
type fileID struct {
	dev uint64
	ino uint64
}

// statPath returns the inode number, mount ID and mode of path.
func statPath(path string) (ino, mountID uint64, mode uint16, err error) {
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_NO_AUTOMOUNT, unix.STATX_INO|unix.STATX_MODE|unix.STATX_MNT_ID, &st); err != nil {
		return 0, 0, 0, err
	}
	if st.Mask&unix.STATX_MNT_ID == 0 {
		return 0, 0, 0, fmt.Errorf("statx %s: kernel reported no mount ID", path)
	}
	return st.Ino, st.Mnt_id, st.Mode, nil
}

// pathFileID keys path by the superblock device of the mount that statx
// reports, from mountinfo, never stat's st_dev, which differs from sb->s_dev
// on btrfs subvolumes.
func pathFileID(path string) (fileID, error) {
	ino, mountID, _, err := statPath(path)
	if err != nil {
		return fileID{}, err
	}
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

func daemonFileID() (fileID, error) {
	exe, err := os.Executable()
	if err != nil {
		return fileID{}, err
	}
	return pathFileID(exe)
}

// Settings: pid@0, active bank@4, daemon dev@8, daemon ino@16, audit@24,
// explicit Rust trailing padding@28.
func encodeSettings(daemonPID, bank uint32, exe fileID, audit bool) []byte {
	b := make([]byte, settingsSize)
	binary.LittleEndian.PutUint32(b[0:], daemonPID)
	binary.LittleEndian.PutUint32(b[4:], bank)
	binary.LittleEndian.PutUint64(b[8:], exe.dev)
	binary.LittleEndian.PutUint64(b[16:], exe.ino)
	if audit {
		binary.LittleEndian.PutUint32(b[24:], 1)
	}
	return b
}

// ObjectKey: dev@0, ino@8, bank@16, explicit trailing padding@20.
func encodeObjectKey(bank uint32, id fileID) []byte {
	b := make([]byte, objectKeySize)
	binary.LittleEndian.PutUint64(b[0:], id.dev)
	binary.LittleEndian.PutUint64(b[8:], id.ino)
	binary.LittleEndian.PutUint32(b[16:], bank)
	return b
}

// ObjectValue: first context@0, context count@4.
func encodeObjectValue(first, count uint32) []byte {
	b := make([]byte, objectValueSize)
	binary.LittleEndian.PutUint32(b[0:], first)
	binary.LittleEndian.PutUint32(b[4:], count)
	return b
}

// Context: path_off, path_len, parent_len, flags, scope_count, rule_count,
// then the ScopeRef (off, len, exclude) and RuleRef (pattern u16, list u8,
// flags u8) arrays.
func encodeContext(c CompiledContext, arena map[string]uint32) []byte {
	b := make([]byte, contextSize)
	pathLen := uint32(len(c.Path))
	if c.Path == "/" {
		pathLen = 0
	}
	binary.LittleEndian.PutUint32(b[0:], arena[c.Path])
	binary.LittleEndian.PutUint32(b[4:], pathLen)
	binary.LittleEndian.PutUint32(b[8:], c.ParentLen)
	if c.Overflow {
		binary.LittleEndian.PutUint32(b[12:], contextOverflow)
		return b
	}
	binary.LittleEndian.PutUint32(b[16:], uint32(len(c.Scopes)))
	binary.LittleEndian.PutUint32(b[20:], uint32(len(c.Rules)))
	for i, scope := range c.Scopes {
		at := 24 + i*scopeRefSize
		binary.LittleEndian.PutUint32(b[at:], arena[scope.Path])
		binary.LittleEndian.PutUint32(b[at+4:], uint32(len(scope.Path)))
		if scope.Exclude {
			binary.LittleEndian.PutUint32(b[at+8:], 1)
		}
	}
	for i, rule := range c.Rules {
		at := 24 + contextScopes*scopeRefSize + i*ruleRefSize
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
