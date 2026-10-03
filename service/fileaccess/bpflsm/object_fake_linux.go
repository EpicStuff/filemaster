//go:build linux && filemaster_test

package bpflsm

// Object is empty in fake-source tests so they do not need the Rust toolchain.
func Object() []byte {
	return nil
}
