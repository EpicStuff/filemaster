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

// Byte layouts of bpf/filemaster-lsm-common's M2 decision-table ABI. The
// committed Rust manifest test guards these constants against layout drift.
const (
	numBanks    = 2
	maxObjects  = 1024
	maxVerdicts = numBanks * maxObjects * 5 * 3 * 2
	maxNoMatch  = numBanks * 5 * 2

	settingsSize   = 32
	objectKeySize  = 24
	verdictKeySize = 24
	noMatchKeySize = 16
	verdictSize    = 4
	auditKeySize   = 4
	auditValueSize = 8

	labelUnidentified = 1
)

var policyMaps = []string{"SETTINGS", "OBJECTS", "VERDICT", "NOMATCH", "AUDIT"}

func checkMapLayout(spec *ebpf.CollectionSpec) error {
	for name, want := range map[string][2]uint32{
		"SETTINGS": {4, settingsSize},
		"OBJECTS":  {objectKeySize, 4},
		"VERDICT":  {verdictKeySize, verdictSize},
		"NOMATCH":  {noMatchKeySize, verdictSize},
		"AUDIT":    {auditKeySize, auditValueSize},
	} {
		m, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("object has no %s map", name)
		}
		if m.KeySize != want[0] || m.ValueSize != want[1] {
			return fmt.Errorf("%s map is key=%d value=%d, loader expects key=%d value=%d", name, m.KeySize, m.ValueSize, want[0], want[1])
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

// pathFileID keys path by the superblock device from mountinfo, not stat's
// st_dev, which differs from sb->s_dev on btrfs subvolumes.
func pathFileID(path string) (fileID, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fileID{}, err
	}
	mounts, err := mountinfo.GetMounts(mountinfo.ParentsFilter(path))
	if err != nil {
		return fileID{}, err
	}
	var best *mountinfo.Info
	for _, m := range mounts {
		if best == nil || len(m.Mountpoint) > len(best.Mountpoint) {
			best = m
		}
	}
	if best == nil {
		return fileID{}, fmt.Errorf("no mount contains %s", path)
	}
	return fileID{dev: uint64(best.Major)<<20 | uint64(best.Minor), ino: st.Ino}, nil
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

// VerdictKey: bank, object, label, operation, relation, kind (all u32).
func encodeVerdictKey(bank, object uint32, operation Operation, relation Relation, kind TargetKind) []byte {
	b := make([]byte, verdictKeySize)
	binary.LittleEndian.PutUint32(b[0:], bank)
	binary.LittleEndian.PutUint32(b[4:], object)
	binary.LittleEndian.PutUint32(b[8:], labelUnidentified)
	binary.LittleEndian.PutUint32(b[12:], uint32(operation))
	binary.LittleEndian.PutUint32(b[16:], uint32(relation))
	binary.LittleEndian.PutUint32(b[20:], uint32(kind))
	return b
}

// NoMatchKey: bank, label, operation, target kind (all u32).
func encodeNoMatchKey(bank uint32, operation Operation, kind TargetKind) []byte {
	b := make([]byte, noMatchKeySize)
	binary.LittleEndian.PutUint32(b[0:], bank)
	binary.LittleEndian.PutUint32(b[4:], labelUnidentified)
	binary.LittleEndian.PutUint32(b[8:], uint32(operation))
	binary.LittleEndian.PutUint32(b[12:], uint32(kind))
	return b
}
