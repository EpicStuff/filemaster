//go:build linux && !filemaster_test

package bpflsm

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func requireBPFLSM(t *testing.T) *btf.Spec {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("BPF LSM tests require root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("kernel BTF unavailable: %v", err)
	}
	// BTF the kernel provides but the loader cannot parse is a loader bug, not
	// a missing prerequisite.
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatalf("parse kernel BTF: %v", err)
	}
	if problems, _ := probe(kernel); len(problems) > 0 {
		t.Skipf("BPF LSM unavailable: %v", problems)
	}
	return kernel
}

func TestLoadEmbeddedObject(t *testing.T) {
	kernel := requireBPFLSM(t)

	spec, err := loadSpec(Object(), kernel)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		t.Fatalf("load embedded BPF object through verifier: %v", verifierError(err))
	}
	defer collection.Close()

	// The kernel's .rodata must hold the offsets loadSpec computed, not the
	// object's zeros.
	offsets := spec.Variables["OFFSETS"]
	if !slices.ContainsFunc(offsets.Value, func(b byte) bool { return b != 0 }) {
		t.Fatal("loadSpec left OFFSETS zero")
	}
	rodata := make([]byte, spec.Maps[".rodata"].ValueSize)
	if err := collection.Maps[".rodata"].Lookup(uint32(0), &rodata); err != nil {
		t.Fatalf("read loaded .rodata: %v", err)
	}
	if loaded := rodata[offsets.Offset : offsets.Offset+offsets.Size()]; !bytes.Equal(loaded, offsets.Value) {
		t.Fatalf("loaded OFFSETS = %x, want %x", loaded, offsets.Value)
	}

	if len(collection.Programs) != len(Hooks)+len(labelPrograms) {
		t.Fatalf("loaded %d programs, want the %d structural hooks and %d labelling programs: %v",
			len(collection.Programs), len(Hooks), len(labelPrograms), collection.Programs)
	}
	var names []string
	for _, hook := range Hooks {
		names = append(names, hook.Program)
	}
	for _, name := range append(names, labelPrograms...) {
		program, ok := collection.Programs[name]
		if !ok {
			t.Errorf("program %q was not loaded", name)
			continue
		}
		info, err := program.Info()
		if err != nil {
			t.Errorf("program %q did not load: %v", name, err)
			continue
		}
		instructions, _ := info.VerifiedInstructions()
		stack := ""
		for _, line := range strings.Split(program.VerifierLog, "\n") {
			if index := strings.Index(line, "stack depth"); index >= 0 {
				stack = line[index:]
			}
		}
		t.Logf("verifier passed: %s, %d verified instructions, %s", name, instructions, stack)
	}
}
