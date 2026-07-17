// fanotify-confined-pipeline verifies the real daemon pipeline on one
// temporary bind mount. It never marks the host root filesystem.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	apiclient "github.com/safing/portmaster/base/api/client"
	"github.com/safing/portmaster/base/database/query"
	"golang.org/x/sys/unix"
)

const (
	modeVerify    = "verify"
	modeBenchmark = "benchmark"
)

type latencySummary struct {
	Count int64   `json:"count"`
	P50MS float64 `json:"p50_ms"`
	P95MS float64 `json:"p95_ms"`
	MaxMS float64 `json:"max_ms"`
}

type result struct {
	Mode                   string         `json:"mode"`
	Scope                  string         `json:"scope"`
	Events                 int            `json:"events"`
	Allowed                int            `json:"allowed"`
	Denied                 int            `json:"denied"`
	Prompts                int            `json:"prompts"`
	QueueSaturationDenies  uint64         `json:"queue_saturation_denies"`
	OutstandingLimitDenies uint64         `json:"outstanding_limit_denies"`
	ProfileAskLimitDenies  uint64         `json:"profile_ask_limit_denies"`
	MaxQueueDepth          int            `json:"max_queue_depth"`
	MaxOutstanding         int64          `json:"max_outstanding_descriptors"`
	FailedResponses        int            `json:"failed_responses"`
	UnresolvedOwnership    int            `json:"unresolved_ownership"`
	DirtyPermanentRules    int            `json:"dirty_permanent_rules"`
	ResponseLatency        latencySummary `json:"response_latency"`
	ObservationVerified    bool           `json:"observation_verified"`
	PersistenceReloaded    bool           `json:"persistence_reloaded"`
	ControlledShutdown     bool           `json:"controlled_shutdown"`
	Kernel                 string         `json:"kernel"`
	CPUCount               int            `json:"cpu_count"`
	Failure                string         `json:"failure,omitempty"`
}

type diagnostics struct {
	Reader struct {
		OutstandingDescriptors int64 `json:"OutstandingDescriptors"`
		PeakOutstanding        int64 `json:"PeakOutstandingDescriptors"`
		Running                bool  `json:"Running"`
		Fatal                  bool  `json:"Fatal"`
	} `json:"Reader"`
	Decision struct {
		QueueDepth              int    `json:"QueueDepth"`
		PeakQueueDepth          int    `json:"PeakQueueDepth"`
		Outstanding             int64  `json:"Outstanding"`
		QueueSaturationDenies   uint64 `json:"QueueSaturationDenies"`
		OutstandingBudgetDenies uint64 `json:"OutstandingBudgetDenies"`
		ProfileAskBudgetDenies  uint64 `json:"ProfileAskBudgetDenies"`
	} `json:"Decision"`
	Prompt struct {
		Groups int `json:"Groups"`
		Events int `json:"Events"`
	} `json:"Prompt"`
	Response struct {
		FatalError string `json:"FatalError"`
	} `json:"Response"`
	FailedResponseCount int `json:"FailedResponseCount"`
	PermanentRules      struct {
		DirtyCount int `json:"DirtyCount"`
	} `json:"PermanentRules"`
}

func main() {
	flags := flag.NewFlagSet("fanotify-confined-pipeline", flag.ExitOnError)
	core := flags.String("core", "", "path to a freshly built portmaster-core executable")
	mode := flags.String("mode", modeVerify, "verify or benchmark")
	events := flags.Int("events", 25, "additional allowed events for benchmark mode")
	output := flags.String("json", "", "optional private JSON result path")
	timeout := flags.Duration("timeout", 90*time.Second, "whole verifier timeout")
	_ = flags.Parse(os.Args[1:])

	res, err := run(*core, *mode, *events, *timeout)
	if err != nil {
		res.Failure = err.Error()
	}
	encoded, marshalErr := json.Marshal(res)
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, marshalErr)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
	if *output != "" {
		if writeErr := writePrivateJSON(*output, encoded); writeErr != nil {
			fmt.Fprintln(os.Stderr, writeErr)
			os.Exit(1)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(core, mode string, events int, timeout time.Duration) (result, error) { //nolint:gocognit
	res := result{Mode: mode, CPUCount: runtimeCPUCount(), Kernel: kernelRelease()}
	if core == "" {
		return res, errors.New("--core is required")
	}
	if mode != modeVerify && mode != modeBenchmark {
		return res, fmt.Errorf("mode must be %q or %q", modeVerify, modeBenchmark)
	}
	if events < 0 {
		return res, errors.New("events must not be negative")
	}
	if os.Geteuid() != 0 {
		return res, errors.New("confined pipeline verifier requires effective UID 0")
	}
	if pidOne, err := os.ReadFile("/proc/1/comm"); err != nil || strings.TrimSpace(string(pidOne)) != "systemd" {
		return res, errors.New("confined pipeline verifier requires PID 1 to be systemd")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	root, err := os.MkdirTemp("", "filemaster-confined-pipeline-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(root)
	source := filepath.Join(root, "source")
	scope := filepath.Join(root, "scope")
	if err := os.Mkdir(source, 0o700); err != nil {
		return res, err
	}
	if err := os.Mkdir(scope, 0o700); err != nil {
		return res, err
	}
	if err := unix.Mount(source, scope, "", unix.MS_BIND, ""); err != nil {
		return res, fmt.Errorf("bind temporary scope: %w", err)
	}
	defer func() { _ = unix.Unmount(scope, unix.MNT_DETACH) }()
	res.Scope = scope

	dataDir := filepath.Join(root, "data")
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return res, err
	}
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return res, err
	}
	config := map[string]any{"core": map[string]any{"devMode": true}, "fileaccess": map[string]any{"watchPaths": []string{scope}, "interceptReads": true}}
	encoded, err := json.Marshal(config)
	if err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.json"), encoded, 0o600); err != nil {
		return res, err
	}
	probe := filepath.Join(scope, "probe")
	if err := os.WriteFile(probe, []byte("confined pipeline\n"), 0o600); err != nil {
		return res, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return res, err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return res, err
	}
	unit := fmt.Sprintf("filemaster-confined-pipeline-%d", os.Getpid())
	if err := startUnit(ctx, unit, core, address, dataDir, binDir); err != nil {
		return res, err
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = stopUnit(context.Background(), unit)
		}
	}()
	if err := waitForAPI(ctx, address); err != nil {
		return res, err
	}

	client := apiclient.NewClient(address)
	defer client.Shutdown()
	go client.StayConnected()
	select {
	case <-client.Online():
	case <-ctx.Done():
		return res, fmt.Errorf("notifications API did not connect: %w", ctx.Err())
	}
	promptMessages := make(chan *apiclient.Message, 32)
	client.Qsub(query.New("notifications:all/").Print(), func(message *apiclient.Message) { promptMessages <- message })
	if err := waitForQsub(ctx, promptMessages); err != nil {
		return res, err
	}

	helperDone := make(chan error, 1)
	go func() { helperDone <- runHelper(ctx, unit+"-prompt", probe) }()
	promptKey, err := waitForPrompt(ctx, promptMessages, probe)
	if err != nil {
		return res, err
	}
	res.Prompts++
	if err := approveAlways(ctx, client, promptKey); err != nil {
		return res, err
	}
	if err := waitForHelper(ctx, helperDone); err != nil {
		return res, err
	}
	res.Allowed++
	res.Events++

	if err := waitForObservation(ctx, address, probe); err != nil {
		return res, err
	}
	res.ObservationVerified = true
	if err := waitForCleanPersistence(ctx, address); err != nil {
		return res, err
	}

	if err := stopUnit(ctx, unit); err != nil {
		return res, err
	}
	stopped = true
	if err := startUnit(ctx, unit, core, address, dataDir, binDir); err != nil {
		return res, err
	}
	stopped = false
	if err := waitForAPI(ctx, address); err != nil {
		return res, err
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- runHelper(ctx, unit+"-reloaded", probe) }()
	if err := waitForHelper(ctx, secondDone); err != nil {
		return res, err
	}
	select {
	case message := <-promptMessages:
		if isPromptFor(message, probe) {
			return res, errors.New("saved Allow always rule prompted after daemon reload")
		}
	default:
	}
	res.PersistenceReloaded = true
	res.Allowed++
	res.Events++

	var samples []time.Duration
	for index := 0; index < events; index++ {
		started := time.Now()
		if err := runHelper(ctx, fmt.Sprintf("%s-bench-%d", unit, index), probe); err != nil {
			return res, err
		}
		samples = append(samples, time.Since(started))
		res.Allowed++
		res.Events++
	}
	res.ResponseLatency = summarize(samples)
	diagnostic, err := getDiagnostics(ctx, address)
	if err != nil {
		return res, err
	}
	res.QueueSaturationDenies = diagnostic.Decision.QueueSaturationDenies
	res.OutstandingLimitDenies = diagnostic.Decision.OutstandingBudgetDenies
	res.ProfileAskLimitDenies = diagnostic.Decision.ProfileAskBudgetDenies
	res.MaxQueueDepth = diagnostic.Decision.PeakQueueDepth
	res.MaxOutstanding = diagnostic.Reader.PeakOutstanding
	res.FailedResponses = diagnostic.FailedResponseCount
	res.DirtyPermanentRules = diagnostic.PermanentRules.DirtyCount
	res.UnresolvedOwnership = diagnostic.Decision.QueueDepth + int(diagnostic.Decision.Outstanding) + diagnostic.Prompt.Events
	if diagnostic.Reader.OutstandingDescriptors != 0 || diagnostic.Decision.Outstanding != 0 || diagnostic.Prompt.Events != 0 {
		return res, fmt.Errorf("pipeline did not drain: reader=%d outstanding=%d prompts=%d", diagnostic.Reader.OutstandingDescriptors, diagnostic.Decision.Outstanding, diagnostic.Prompt.Events)
	}
	if err := stopUnit(ctx, unit); err != nil {
		return res, err
	}
	stopped = true
	res.ControlledShutdown = true
	return res, nil
}

func startUnit(ctx context.Context, unit, core, address, dataDir, binDir string) error {
	command := exec.CommandContext(ctx, "systemd-run", "--unit="+unit, "--collect", "--property=Type=simple", core, "--devmode", "--log", "debug", "--api-address", address, "--data-dir", dataDir, "--bin-dir", binDir)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start Filemaster systemd unit: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func stopUnit(ctx context.Context, unit string) error {
	command := exec.CommandContext(ctx, "systemctl", "stop", unit+".service")
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("stop Filemaster systemd unit: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runHelper(ctx context.Context, unit, path string) error {
	command := exec.CommandContext(ctx, "systemd-run", "--unit="+unit, "--collect", "--wait", "--pipe", "/bin/cat", path)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd helper access: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForAPI(ctx context.Context, address string) error {
	client := &http.Client{Timeout: time.Second}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/fileaccess/diagnostics", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil && response.StatusCode == http.StatusOK {
			_ = response.Body.Close()
			return nil
		}
		if response != nil {
			_ = response.Body.Close()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Filemaster API: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitForQsub(ctx context.Context, messages <-chan *apiclient.Message) error {
	for {
		select {
		case message := <-messages:
			if message.Type == apiclient.MsgDone {
				return nil
			}
			if message.Type == apiclient.MsgError || message.Type == apiclient.MsgWarning {
				return fmt.Errorf("notification subscription: %s %s", message.Type, message.Key)
			}
		case <-ctx.Done():
			return fmt.Errorf("wait for notification subscription: %w", ctx.Err())
		}
	}
}

func waitForPrompt(ctx context.Context, messages <-chan *apiclient.Message, path string) (string, error) {
	for {
		select {
		case message := <-messages:
			if isPromptFor(message, path) {
				return message.Key, nil
			}
		case <-ctx.Done():
			return "", fmt.Errorf("wait for prompt for %s: %w", path, ctx.Err())
		}
	}
}

func isPromptFor(message *apiclient.Message, path string) bool {
	return message != nil && message.Type == apiclient.MsgNew && strings.HasPrefix(message.Key, "notifications:all/fileaccess:") && strings.Contains(string(message.RawValue), path)
}

func approveAlways(ctx context.Context, client *apiclient.Client, key string) error {
	updated := make(chan *apiclient.Message, 1)
	client.Update(key, map[string]string{"SelectedActionID": "allow-always"}, func(message *apiclient.Message) { updated <- message })
	select {
	case message := <-updated:
		if message.Type != apiclient.MsgSuccess {
			return fmt.Errorf("approve prompt: %s %s", message.Type, message.Key)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("approve prompt: %w", ctx.Err())
	}
}

func waitForHelper(ctx context.Context, done <-chan error) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("wait for systemd helper: %w", ctx.Err())
	}
}

func waitForObservation(ctx context.Context, address, path string) error {
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/api/v1/filequery/query", strings.NewReader(`{"pageSize":20}`))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			var payload any
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			_ = response.Body.Close()
			if decodeErr == nil && strings.Contains(fmt.Sprint(payload), path) && strings.Contains(fmt.Sprint(payload), "allow") {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for file observation: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func waitForCleanPersistence(ctx context.Context, address string) error {
	for {
		diagnostic, err := getDiagnostics(ctx, address)
		if err == nil && diagnostic.PermanentRules.DirtyCount == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for permanent rule persistence: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func getDiagnostics(ctx context.Context, address string) (diagnostics, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/fileaccess/diagnostics", nil)
	if err != nil {
		return diagnostics{}, err
	}
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		return diagnostics{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return diagnostics{}, fmt.Errorf("diagnostics status %s", response.Status)
	}
	var diagnostic diagnostics
	if err := json.NewDecoder(response.Body).Decode(&diagnostic); err != nil {
		return diagnostics{}, err
	}
	return diagnostic, nil
}

func summarize(samples []time.Duration) latencySummary {
	if len(samples) == 0 {
		return latencySummary{}
	}
	ordered := append([]time.Duration(nil), samples...)
	for index := 1; index < len(ordered); index++ {
		for previous := index; previous > 0 && ordered[previous] < ordered[previous-1]; previous-- {
			ordered[previous], ordered[previous-1] = ordered[previous-1], ordered[previous]
		}
	}
	toMS := func(value time.Duration) float64 { return float64(value.Microseconds()) / 1000 }
	return latencySummary{Count: int64(len(ordered)), P50MS: toMS(ordered[(len(ordered)-1)/2]), P95MS: toMS(ordered[(len(ordered)*95+99)/100-1]), MaxMS: toMS(ordered[len(ordered)-1])}
}

func writePrivateJSON(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func kernelRelease() string {
	var info unix.Utsname
	if unix.Uname(&info) != nil {
		return "unknown"
	}
	var builder strings.Builder
	for _, value := range info.Release {
		if value == 0 {
			break
		}
		builder.WriteByte(byte(value))
	}
	return builder.String()
}

func runtimeCPUCount() int { return runtime.NumCPU() }
