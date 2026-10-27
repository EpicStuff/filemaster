//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
	"github.com/moby/sys/mountinfo"
)

// btrfsEmptySubvolumeDir is BTRFS_EMPTY_SUBVOL_DIR_OBJECTID.
const btrfsEmptySubvolumeDir = 2

// btrfsLayout locates a btrfs inode's subvolume from its struct inode:
// BTRFS_I(inode)->root->root_key.objectid, which btrfs's getattr reports as
// STATX_SUBVOL on 6.10 and later. root is btrfs_inode.root's offset relative
// to btrfs_inode.vfs_inode, and rootID is root_key.objectid's offset in
// btrfs_root.
type btrfsLayout struct {
	ok     bool
	root   int32
	rootID uint32
}

// btrfsLayoutSource is currentBtrfsLayout, replaceable by tests that need a
// kernel whose btrfs layout cannot be read.
var btrfsLayoutSource = currentBtrfsLayout

var btrfsLayouts struct {
	sync.Mutex
	layout btrfsLayout
}

// currentBtrfsLayout reads the layout from the running kernel's BTF: vmlinux
// when btrfs is built in, else the btrfs module's BTF, which exists only while
// the module is loaded. A resolved layout is kept; a failure is retried at the
// next call.
func currentBtrfsLayout() (btrfsLayout, error) {
	btrfsLayouts.Lock()
	defer btrfsLayouts.Unlock()
	if btrfsLayouts.layout.ok {
		return btrfsLayouts.layout, nil
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return btrfsLayout{}, fmt.Errorf("load kernel BTF: %w", err)
	}
	var inode *btf.Struct
	if err := spec.TypeByName("btrfs_inode", &inode); errors.Is(err, btf.ErrNotFound) {
		if spec, err = btf.LoadKernelModuleSpec("btrfs"); err != nil {
			return btrfsLayout{}, fmt.Errorf("load btrfs module BTF: %w", err)
		}
	}
	layout, err := btrfsLayoutFrom(spec)
	if err != nil {
		return btrfsLayout{}, err
	}
	btrfsLayouts.layout = layout
	return layout, nil
}

func btrfsLayoutFrom(spec *btf.Spec) (btrfsLayout, error) {
	member := func(structName string, path ...string) (uint32, btf.Type, error) {
		var structure *btf.Struct
		if err := spec.TypeByName(structName, &structure); err != nil {
			return 0, nil, fmt.Errorf("find BTF struct %q: %w", structName, err)
		}
		var typ btf.Type = structure
		var offset uint32
		for _, name := range path {
			memberOffset, next, ok := findBTFMember(typ, name)
			if !ok {
				return 0, nil, fmt.Errorf("find BTF member %q in %q", name, structName)
			}
			offset += memberOffset
			typ = next
		}
		return offset, btf.UnderlyingType(typ), nil
	}
	vfsInode, vfsType, err := member("btrfs_inode", "vfs_inode")
	if err != nil {
		return btrfsLayout{}, err
	}
	if structure, ok := vfsType.(*btf.Struct); !ok || structure.Name != "inode" {
		return btrfsLayout{}, fmt.Errorf("btrfs_inode.vfs_inode is %v, not struct inode", vfsType)
	}
	root, rootType, err := member("btrfs_inode", "root")
	if err != nil {
		return btrfsLayout{}, err
	}
	if _, ok := rootType.(*btf.Pointer); !ok {
		return btrfsLayout{}, fmt.Errorf("btrfs_inode.root is %v, not a pointer", rootType)
	}
	rootID, idType, err := member("btrfs_root", "root_key", "objectid")
	if err != nil {
		return btrfsLayout{}, err
	}
	if integer, ok := idType.(*btf.Int); !ok || integer.Size != 8 {
		return btrfsLayout{}, fmt.Errorf("btrfs_root.root_key.objectid is %v, not a 64-bit integer", idType)
	}
	return btrfsLayout{ok: true, root: int32(int64(root) - int64(vfsInode)), rootID: rootID}, nil
}

// objectSubvolume is the subvolume part of an object's identity as the kernel
// computes it: the btrfs subvolume when the kernel can read it, and 0 on any
// other filesystem. known is false for a filesystem whose subvolumes the
// kernel cannot tell apart: btrfs without a readable layout or STATX_SUBVOL,
// or any other filesystem that reports STATX_SUBVOL (bcachefs).
func objectSubvolume(fsType string, st pathStat, btrfs btrfsLayout) (subvol uint64, known bool) {
	if fsType == "btrfs" {
		if btrfs.ok && st.hasSubvol {
			return st.subvol, true
		}
		return 0, false
	}
	return 0, !st.hasSubvol
}

// markUnknownSubvolumes makes every context on a covered filesystem in
// unknown deny: its inode numbers may repeat across subvolumes, so a walk may
// stop at an object of another subvolume and take its path. The warning names
// the mounts and why btrfs's layout was not read, if it was not.
func markUnknownSubvolumes(table *Table, unknown, anchored map[uint64]bool, mounts []*mountinfo.Info, scopes []ScopeInput, literals []string, btrfsErr error, warnings warningSet) {
	mountpoints := coveredMountpoints(unknown, anchored, mounts, scopes, literals)
	for _, object := range table.Objects {
		if !unknown[object.File.dev] || !coveredDevice(object.File.dev, anchored, mounts, scopes, literals) {
			continue
		}
		for index := object.FirstContext; index < object.FirstContext+object.ContextCount; index++ {
			table.Contexts[index].Subvolume = true
		}
	}
	for _, mountpoint := range mountpoints {
		warnings.add("subvolume-identity-unknown", mountpoint)
	}
	if len(mountpoints) > 0 && btrfsErr != nil {
		warnings.add("subvolume-identity-unknown", "btrfs layout: "+btrfsErr.Error())
	}
}

// coveredMountpoints lists, sorted and with their filesystem type, the mounts
// of the superblocks in devs that a scope or rule can decide a target on.
func coveredMountpoints(devs, anchored map[uint64]bool, mounts []*mountinfo.Info, scopes []ScopeInput, literals []string) []string {
	var mountpoints []string
	for _, mount := range mounts {
		if dev := deviceID(mount); devs[dev] && coveredDevice(dev, anchored, mounts, scopes, literals) {
			mountpoints = append(mountpoints, mount.Mountpoint+" ("+mount.FSType+")")
		}
	}
	sort.Strings(mountpoints)
	return mountpoints
}

// coveredDevice reports whether a scope or rule can decide a target on the
// superblock dev: one anchors on it (anchored), or one of its mounts lies
// inside a scope or below a rule's literal prefix.
func coveredDevice(dev uint64, anchored map[uint64]bool, mounts []*mountinfo.Info, scopes []ScopeInput, literals []string) bool {
	if anchored[dev] {
		return true
	}
	for _, mount := range mounts {
		if deviceID(mount) != dev {
			continue
		}
		for _, scope := range scopes {
			if !scope.Exclude && pathContains(scope.Path, mount.Mountpoint) {
				return true
			}
		}
		for _, literal := range literals {
			if strings.HasPrefix(mount.Mountpoint, literal) {
				return true
			}
		}
	}
	return false
}
