//go:build linux && !filemaster_test

package bpflsm

import (
	"os"
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
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load embedded BPF object through verifier: %v", verifierError(err))
	}
	defer collection.Close()

	if len(collection.Programs) != len(Hooks) {
		t.Fatalf("loaded %d programs, want only the %d structural hooks: %v", len(collection.Programs), len(Hooks), collection.Programs)
	}
	for _, hook := range Hooks {
		program, ok := collection.Programs[hook.Program]
		if !ok {
			t.Errorf("program %q was not loaded", hook.Program)
			continue
		}
		if _, err := program.Info(); err != nil {
			t.Errorf("program %q did not load: %v", hook.Program, err)
			continue
		}
		t.Logf("verifier passed: %s", hook.Program)
	}
}
