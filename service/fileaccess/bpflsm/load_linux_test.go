//go:build linux && !filemaster_test

package bpflsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestLoadEmbeddedObject(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("BPF verifier load test requires root")
	}

	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Skipf("BPF LSM unavailable: cannot read active LSMs: %v", err)
	}
	if !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,") {
		t.Skip("BPF LSM is not active on this kernel")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(Object()))
	if err != nil {
		t.Fatalf("parse embedded BPF object: %v", err)
	}

	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("load kernel BTF: %v", err)
	}
	offsets := []uint32{
		memberOffset(t, kernelSpec, "file", "f_path", "dentry"),
		memberOffset(t, kernelSpec, "file", "f_inode"),
		memberOffset(t, kernelSpec, "file", "f_mode"),
		memberOffset(t, kernelSpec, "file", "f_flags"),
		memberOffset(t, kernelSpec, "dentry", "d_inode"),
		memberOffset(t, kernelSpec, "dentry", "d_sb"),
		memberOffset(t, kernelSpec, "dentry", "d_parent"),
		memberOffset(t, kernelSpec, "dentry", "d_name", "name"),
		memberOffset(t, kernelSpec, "inode", "i_ino"),
		memberOffset(t, kernelSpec, "inode", "i_sb"),
		memberOffset(t, kernelSpec, "super_block", "s_dev"),
		memberOffset(t, kernelSpec, "task_struct", "mm"),
		memberOffset(t, kernelSpec, "mm_struct", "exe_file"),
		memberOffset(t, kernelSpec, "linux_binprm", "file"),
	}

	variable, ok := spec.Variables["OFFSETS"]
	if !ok {
		t.Fatal("embedded BPF object has no OFFSETS variable")
	}
	rodata, ok := spec.Maps[".rodata"]
	if !ok || len(rodata.Contents) == 0 {
		t.Fatal("embedded BPF object has no .rodata contents")
	}
	bytes, ok := rodata.Contents[0].Value.([]byte)
	if !ok {
		t.Fatalf("embedded BPF .rodata has unexpected value type %T", rodata.Contents[0].Value)
	}
	for index, offset := range offsets {
		start := int(variable.Offset()) + index*4
		if start+4 > len(bytes) {
			t.Fatalf("OFFSETS member %d exceeds .rodata (%d bytes)", index, len(bytes))
		}
		binary.LittleEndian.PutUint32(bytes[start:], offset)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifierError *ebpf.VerifierError
		if errors.As(err, &verifierError) {
			t.Fatalf("load embedded BPF object through verifier: %v\nverifier log tail:\n%s", err, strings.Join(verifierError.Log, "\n"))
		}
		t.Fatalf("load embedded BPF object through verifier: %v", err)
	}
	defer collection.Close()

	want := []string{"inode_link", "inode_rename", "inode_unlink", "inode_rmdir", "inode_mkdir"}
	if len(collection.Programs) != len(want) {
		t.Fatalf("loaded %d programs, want only the five structural hooks: %v", len(collection.Programs), collection.Programs)
	}
	for _, name := range want {
		program, ok := collection.Programs[name]
		if !ok {
			t.Errorf("program %q was not loaded", name)
			continue
		}
		if _, err := program.Info(); err != nil {
			t.Errorf("program %q did not load: %v", name, err)
			continue
		}
		t.Logf("verifier passed: %s", name)
	}
}

func memberOffset(t *testing.T, spec *btf.Spec, structName string, path ...string) uint32 {
	t.Helper()

	var structure *btf.Struct
	if err := spec.TypeByName(structName, &structure); err != nil {
		t.Fatalf("find BTF struct %q: %v", structName, err)
	}

	var typ btf.Type = structure
	var offset uint32
	for _, name := range path {
		memberOffset, next, ok := findBTFMember(typ, name)
		if !ok {
			t.Fatalf("find BTF member %q in %q", name, structName)
		}
		offset += memberOffset
		typ = next
	}
	return offset
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
