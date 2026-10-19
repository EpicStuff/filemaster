//go:build linux && !filemaster_test

package bpflsm

import (
	"os"
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
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("kernel BTF unavailable: %v", err)
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
