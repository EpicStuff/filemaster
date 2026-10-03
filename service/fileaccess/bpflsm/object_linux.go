//go:build linux && !filemaster_test

package bpflsm

import _ "embed"

//go:embed obj/filemaster-lsm.bpf.o
var object []byte

// Object returns the embedded BPF LSM ELF for the verifier load test.
func Object() []byte {
	return object
}
