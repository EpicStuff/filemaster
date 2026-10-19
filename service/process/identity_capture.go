package process

import "sync"

// filemaster-specific: the pre-captured command line and environment hook used
// by the BPF labelling boundary in loadProcess. It is not part of upstream
// Portmaster. A single provider is registered by the file-access module; it
// supplies a process's argv and envp as the kernel read them from the new
// image's stack at exec time, so identity cannot be rewritten afterwards.

var (
	identityCaptureMu       sync.RWMutex
	identityCaptureProvider func(pid int32) (cmdline string, env []string, ok bool)
)

// SetIdentityCaptureProvider registers (or, with nil, clears) the provider that
// loadProcess consults before reading cmdline and env from /proc.
func SetIdentityCaptureProvider(provider func(pid int32) (cmdline string, env []string, ok bool)) {
	identityCaptureMu.Lock()
	defer identityCaptureMu.Unlock()
	identityCaptureProvider = provider
}

func preCapturedIdentity(pid int32) (cmdline string, env []string, ok bool) {
	identityCaptureMu.RLock()
	provider := identityCaptureProvider
	identityCaptureMu.RUnlock()
	if provider == nil {
		return "", nil, false
	}
	return provider(pid)
}
