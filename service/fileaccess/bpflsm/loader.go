//go:build linux

package bpflsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/moby/sys/mountinfo"
)

// Hook is one structural LSM program and the Filemaster operation it gates.
type Hook struct {
	Program   string
	Operation string
}

// Hooks lists the structural programs in attach order.
var Hooks = []Hook{
	{"inode_unlink", "delete file"},
	{"inode_rmdir", "delete folder"},
	{"inode_mkdir", "create folder"},
	{"inode_link", "hard link"},
	{"inode_rename", "rename/move"},
}

// probe returns the reasons BPF LSM cannot run on this kernel, and the hooks
// whose BTF attach target is missing.
func probe(kernel *btf.Spec) (problems []string, missingHooks map[string]string) {
	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	switch {
	case err != nil:
		problems = append(problems, fmt.Sprintf("cannot read active LSMs: %v", err))
	case !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,"):
		problems = append(problems, "bpf is not in the active LSM list (boot with lsm=...,bpf)")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		problems = append(problems, fmt.Sprintf("kernel BTF unavailable: %v", err))
	}
	if mounted, err := mountinfo.Mounted("/sys/fs/bpf"); err != nil || !mounted {
		problems = append(problems, "bpffs is not mounted at /sys/fs/bpf")
	}
	if kernel == nil {
		return problems, nil
	}
	missingHooks = make(map[string]string)
	for _, hook := range Hooks {
		var fn *btf.Func
		if err := kernel.TypeByName("bpf_lsm_"+hook.Program, &fn); err != nil {
			missingHooks[hook.Program] = fmt.Sprintf("kernel has no bpf_lsm_%s: %v", hook.Program, err)
		}
	}
	return problems, missingHooks
}

// loadSpec parses the embedded object and writes the running kernel's struct
// offsets into its OFFSETS global, as raw .rodata bytes.
func loadSpec(object []byte, kernel *btf.Spec) (*ebpf.CollectionSpec, error) {
	if len(object) == 0 {
		return nil, errors.New("no BPF object is embedded in this build")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("parse embedded BPF object: %w", err)
	}
	if err := checkMapLayout(spec); err != nil {
		return nil, err
	}

	// Order matches the Offsets struct in filemaster-lsm-common/src/offsets.rs.
	fields := []struct {
		structName string
		path       []string
	}{
		{"file", []string{"f_path", "dentry"}},
		{"file", []string{"f_inode"}},
		{"file", []string{"f_mode"}},
		{"file", []string{"f_flags"}},
		{"dentry", []string{"d_inode"}},
		{"dentry", []string{"d_sb"}},
		{"dentry", []string{"d_parent"}},
		{"dentry", []string{"d_name", "name"}},
		{"dentry", []string{"d_name", "len"}},
		{"inode", []string{"i_ino"}},
		{"inode", []string{"i_mode"}},
		{"inode", []string{"i_sb"}},
		{"super_block", []string{"s_dev"}},
		{"task_struct", []string{"mm"}},
		{"mm_struct", []string{"exe_file"}},
		{"linux_binprm", []string{"file"}},
		{"task_struct", []string{"tgid"}},
		{"task_struct", []string{"group_leader"}},
		{"task_struct", []string{"start_boottime"}},
		{"task_struct", []string{"signal"}},
		{"signal_struct", []string{"live"}},
		{"mm_struct", []string{"arg_start"}},
		{"mm_struct", []string{"arg_end"}},
		{"mm_struct", []string{"env_start"}},
		{"mm_struct", []string{"env_end"}},
		{"inode", []string{"i_generation"}},
		{"linux_binprm", []string{"filename"}},
		{"linux_binprm", []string{"interp"}},
	}
	variable, ok := spec.Variables["OFFSETS"]
	if !ok {
		return nil, errors.New("BPF object has no OFFSETS variable")
	}
	rodata, ok := spec.Maps[".rodata"]
	if !ok || len(rodata.Contents) == 0 {
		return nil, errors.New("BPF object has no .rodata contents")
	}
	data, ok := rodata.Contents[0].Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("BPF .rodata has unexpected value type %T", rodata.Contents[0].Value)
	}
	if int(variable.Size()) != 4*len(fields) {
		return nil, fmt.Errorf("OFFSETS is %d bytes, loader writes %d", variable.Size(), 4*len(fields))
	}
	for index, field := range fields {
		offset, err := memberOffset(kernel, field.structName, field.path...)
		if err != nil {
			return nil, err
		}
		start := int(variable.Offset()) + index*4
		if start+4 > len(data) {
			return nil, fmt.Errorf("OFFSETS member %d exceeds .rodata (%d bytes)", index, len(data))
		}
		binary.LittleEndian.PutUint32(data[start:], offset)
	}
	return spec, nil
}

func memberOffset(kernel *btf.Spec, structName string, path ...string) (uint32, error) {
	var structure *btf.Struct
	if err := kernel.TypeByName(structName, &structure); err != nil {
		return 0, fmt.Errorf("find BTF struct %q: %w", structName, err)
	}
	var typ btf.Type = structure
	var offset uint32
	for _, name := range path {
		memberOffset, next, ok := findBTFMember(typ, name)
		if !ok {
			return 0, fmt.Errorf("find BTF member %q in %q", name, structName)
		}
		offset += memberOffset
		typ = next
	}
	return offset, nil
}

func findBTFMember(typ btf.Type, want string) (uint32, btf.Type, bool) {
	var members []btf.Member
	switch value := btf.UnderlyingType(typ).(type) {
	case *btf.Struct:
		members = value.Members
	case *btf.Union:
		members = value.Members
	default:
		return 0, nil, false
	}
	for _, member := range members {
		if member.Name == want {
			return member.Offset.Bytes(), member.Type, true
		}
		if member.Name == "" {
			if offset, nested, ok := findBTFMember(member.Type, want); ok {
				return member.Offset.Bytes() + offset, nested, true
			}
		}
	}
	return 0, nil, false
}

func verifierError(err error) error {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		lines := verr.Log
		if len(lines) > 30 {
			lines = lines[len(lines)-30:]
		}
		return fmt.Errorf("%w\nverifier log tail:\n%s", err, strings.Join(lines, "\n"))
	}
	return err
}
