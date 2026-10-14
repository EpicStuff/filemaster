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

// Byte layouts of the Rust records in bpf/filemaster-lsm-common. M2 replaces
// these with the manifest-tested decision-table schema; until then checkMapLayout
// refuses an object whose sizes disagree.
const (
	numBanks       = 2
	maxObjects     = 1024
	maxRulesPerObj = 32

	settingsSize     = 24
	bankedFileSize   = 24
	bankedObjSize    = 8
	compiledRuleSize = 48

	actionWrite  = 1 << 1
	actionCreate = 1 << 2

	policyAllow = 0

	subjectAnyAll = 0xf
)

var policyMaps = []string{"SETTINGS", "PROTECTED", "RULES", "RULE_COUNT"}

func checkMapLayout(spec *ebpf.CollectionSpec) error {
	for name, want := range map[string][2]uint32{
		"SETTINGS":   {4, settingsSize},
		"PROTECTED":  {bankedFileSize, 4},
		"RULES":      {4, compiledRuleSize},
		"RULE_COUNT": {bankedObjSize, 4},
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

func encodeSettings(daemonPid uint32, bank uint32, exe fileID) []byte {
	b := make([]byte, settingsSize)
	binary.LittleEndian.PutUint32(b[0:], daemonPid)
	binary.LittleEndian.PutUint32(b[4:], bank)
	binary.LittleEndian.PutUint64(b[8:], exe.dev)
	binary.LittleEndian.PutUint64(b[16:], exe.ino)
	return b
}

func encodeBankedFile(bank uint32, id fileID) []byte {
	b := make([]byte, bankedFileSize)
	binary.LittleEndian.PutUint64(b[0:], id.dev)
	binary.LittleEndian.PutUint64(b[8:], id.ino)
	binary.LittleEndian.PutUint32(b[16:], bank)
	return b
}

func encodeBankedObj(bank uint32, obj uint32) []byte {
	b := make([]byte, bankedObjSize)
	binary.LittleEndian.PutUint32(b[0:], obj)
	binary.LittleEndian.PutUint32(b[4:], bank)
	return b
}

// encodeAnySubjectRule is a rule whose subject matches every caller.
func encodeAnySubjectRule(actions uint32, policy uint8) []byte {
	b := make([]byte, compiledRuleSize)
	binary.LittleEndian.PutUint32(b[32:], subjectAnyAll)
	binary.LittleEndian.PutUint32(b[40:], actions)
	b[44] = policy
	return b
}

func ruleSlot(bank, obj, index uint32) uint32 {
	return (bank*maxObjects+obj)*maxRulesPerObj + index
}
