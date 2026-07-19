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
	"strconv"
	"strings"
	"time"

	apiclient "github.com/safing/portmaster/base/api/client"
	"github.com/safing/portmaster/base/database/query"
	"github.com/safing/structures/dsd"
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

type helperIdentity struct {
	ProfileSource string `json:"profile_source"`
	ProfileID     string `json:"profile_id"`
	ProfileName   string `json:"profile_name"`
	ProfilePath   string `json:"profile_linked_path"`
	Executable    string `json:"executable"`
	Operation     string `json:"operation"`
}

type promptIdentity struct {
	Key      string
	Identity helperIdentity
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
	DecisionLatency        latencySummary `json:"decision_latency"`
	ResponseLatency        latencySummary `json:"response_latency"`
	FirstHelper            helperIdentity `json:"first_helper"`
	SecondHelper           helperIdentity `json:"second_helper,omitempty"`
	ObservationVerified    bool           `json:"observation_verified"`
	PersistenceReloaded    bool           `json:"persistence_reloaded"`
	ControlledShutdown     bool           `json:"controlled_shutdown"`
	Kernel                 string         `json:"kernel"`
	CPUCount               int            `json:"cpu_count"`
	ContainerID            string         `json:"container_id"`
	MountNamespace         string         `json:"mount_namespace"`
	Failure                string         `json:"failure,omitempty"`
}

type diagnostics struct {
	Reader struct {
		OutstandingDescriptors int64  `json:"OutstandingDescriptors"`
		PeakOutstanding        int64  `json:"PeakOutstandingDescriptors"`
		DecisionResponses      uint64 `json:"DecisionResponseCount"`
		LastDecisionLatency    int64  `json:"LastDecisionLatencyNanos"`
		Running                bool   `json:"Running"`
		Fatal                  bool   `json:"Fatal"`
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
	probeHelper := flags.Bool("probe-helper", false, "run one stable systemd helper file-open probe")
	probePath := flags.String("probe", "", "probe path for --probe-helper")
	notifyAddress := flags.String("notify", "", "optional loopback timing address for --probe-helper")
	mode := flags.String("mode", modeVerify, "verify or benchmark")
	events := flags.Int("events", 25, "additional allowed events for benchmark mode")
	rootScope := flags.Bool("root-scope", false, "mark container / after explicit root benchmark acknowledgement")
	output := flags.String("json", "", "optional private JSON result path")
	timeout := flags.Duration("timeout", 90*time.Second, "whole verifier timeout")
	_ = flags.Parse(os.Args[1:])
	if *probeHelper {
		if err := runProbeHelper(*probePath, *notifyAddress); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	var outputFile *os.File
	var err error
	if *output != "" {
		outputFile, err = preparePrivateJSON(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	res, err := run(*core, *mode, *events, *timeout, *rootScope)
	if err != nil {
		res.Failure = err.Error()
	}
	encoded, marshalErr := json.Marshal(res)
	if marshalErr != nil {
		fmt.Fprintln(os.Stderr, marshalErr)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
	if outputFile != nil {
		if writeErr := commitPrivateJSON(*output, outputFile, encoded); writeErr != nil {
			fmt.Fprintln(os.Stderr, writeErr)
			os.Exit(1)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(core, mode string, events int, timeout time.Duration, rootScope bool) (result, error) { //nolint:gocognit
	res := result{Mode: mode, CPUCount: runtimeCPUCount(), Kernel: kernelRelease(), ContainerID: containerID(), MountNamespace: mountNamespace()}
	if core == "" {
		return res, errors.New("--core is required")
	}
	if mode != modeVerify && mode != modeBenchmark {
		return res, fmt.Errorf("mode must be %q or %q", modeVerify, modeBenchmark)
	}
	if events < 0 {
		return res, errors.New("events must not be negative")
	}
	if mode == modeVerify {
		events = 0
	}
	if os.Geteuid() != 0 {
		return res, errors.New("confined pipeline verifier requires effective UID 0")
	}
	if pidOne, err := os.ReadFile("/proc/1/comm"); err != nil || strings.TrimSpace(string(pidOne)) != "systemd" {
		return res, errors.New("confined pipeline verifier requires PID 1 to be systemd")
	}
	if rootScope {
		if os.Getenv("FM_ROOT_BENCHMARK_ACK") != "I_UNDERSTAND_ROOT_MARKING" {
			return res, errors.New("refusing to mark / without FM_ROOT_BENCHMARK_ACK=I_UNDERSTAND_ROOT_MARKING")
		}
		if res.ContainerID == "" {
			return res, errors.New("refusing to mark / outside a Podman container")
		}
		if !isolatedMountNamespace() {
			return res, errors.New("refusing to mark / from a shared mount namespace")
		}
		if !hasCapability(21) {
			return res, errors.New("root benchmark requires effective CAP_SYS_ADMIN")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	root, err := os.MkdirTemp("", "filemaster-confined-pipeline-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(root)
	scope := filepath.Join(root, "scope")
	if rootScope {
		scope = "/"
		fmt.Fprintf(os.Stderr, "root benchmark preflight: container=%s mount_namespace=%s scope=/ timeout=%s cleanup=installed\n", res.ContainerID, res.MountNamespace, timeout)
	} else {
		source := filepath.Join(root, "source")
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
	}
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
	probe := filepath.Join(root, "probe")
	if !rootScope {
		probe = filepath.Join(scope, "probe")
	}
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
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = stopUnit(cleanup, unit)
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

	helperExecutable, err := os.Executable()
	if err != nil {
		return res, fmt.Errorf("resolve stable helper executable: %w", err)
	}
	helperUnit := unit + "-helper"
	helperDone := make(chan error, 1)
	go func() { helperDone <- runHelper(ctx, helperUnit, helperExecutable, probe, "") }()
	prompt, err := waitForPrompt(ctx, promptMessages, probe)
	if err != nil {
		return res, err
	}
	res.FirstHelper = prompt.Identity
	res.Prompts++
	if err := approveAlways(ctx, client, prompt.Key); err != nil {
		return res, err
	}
	if err := waitForHelper(ctx, helperDone); err != nil {
		return res, err
	}
	res.Allowed++
	res.Events++

	firstObservation, observations, err := waitForObservation(ctx, address, probe, 1)
	if err != nil {
		return res, err
	}
	if res.FirstHelper.ProfileSource != firstObservation.ProfileSource || res.FirstHelper.ProfileID != firstObservation.ProfileID || res.FirstHelper.Executable != firstObservation.Executable {
		return res, fmt.Errorf("prompt and observation identity differ: prompt=%+v observation=%+v", res.FirstHelper, firstObservation)
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

drainPromptMessages:
	for {
		select {
		case <-promptMessages:
		default:
			break drainPromptMessages
		}
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- runHelper(ctx, helperUnit, helperExecutable, probe, "") }()
	if err := waitForHelper(ctx, secondDone); err != nil {
		return res, err
	}
	select {
	case message := <-promptMessages:
		if isPromptFor(message, probe) {
			prompt, err := promptIdentityFromMessage(message)
			if err != nil {
				return res, err
			}
			res.SecondHelper = prompt.Identity
			return res, fmt.Errorf("saved Allow always rule prompted after daemon reload: first=%+v second=%+v", res.FirstHelper, res.SecondHelper)
		}
	default:
	}
	secondObservation, _, err := waitForObservation(ctx, address, probe, observations+1)
	if err != nil {
		return res, err
	}
	res.SecondHelper = secondObservation
	if res.FirstHelper.ProfileSource != res.SecondHelper.ProfileSource || res.FirstHelper.ProfileID != res.SecondHelper.ProfileID || res.FirstHelper.Executable != res.SecondHelper.Executable {
		return res, fmt.Errorf("helper identity changed after restart: first=%+v second=%+v", res.FirstHelper, res.SecondHelper)
	}
	res.PersistenceReloaded = true
	res.Allowed++
	res.Events++

	var decisionSamples []time.Duration
	var responseSamples []time.Duration
	for index := 0; index < events; index++ {
		before, err := getDiagnostics(ctx, address)
		if err != nil {
			return res, err
		}
		latency, err := measureHelper(ctx, fmt.Sprintf("%s-bench-%d", unit, index), helperExecutable, probe)
		if err != nil {
			return res, err
		}
		after, err := getDiagnostics(ctx, address)
		if err != nil {
			return res, err
		}
		if after.Reader.DecisionResponses != before.Reader.DecisionResponses+1 {
			return res, fmt.Errorf("decision latency sample contaminated by %d concurrent responses", after.Reader.DecisionResponses-before.Reader.DecisionResponses)
		}
		decisionSamples = append(decisionSamples, time.Duration(after.Reader.LastDecisionLatency))
		responseSamples = append(responseSamples, latency)
		res.Allowed++
		res.Events++
	}
	res.DecisionLatency = summarize(decisionSamples)
	res.ResponseLatency = summarize(responseSamples)
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

func runHelper(ctx context.Context, unit, executable, path, notify string) error {
	arguments := []string{"--unit=" + unit, "--collect", "--wait", "--pipe", executable, "--probe-helper", "--probe", path}
	if notify != "" {
		arguments = append(arguments, "--notify", notify)
	}
	command := exec.CommandContext(ctx, "systemd-run", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd helper access: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runProbeHelper(path, notify string) error {
	if path == "" {
		return errors.New("--probe is required with --probe-helper")
	}
	var connection net.Conn
	var err error
	if notify != "" {
		connection, err = net.DialTimeout("tcp", notify, time.Second)
		if err != nil {
			return fmt.Errorf("connect probe timing channel: %w", err)
		}
		defer connection.Close()
		if _, err := fmt.Fprintln(connection, "before"); err != nil {
			return fmt.Errorf("notify probe start: %w", err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open probe: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close probe: %w", err)
	}
	if connection != nil {
		if _, err := fmt.Fprintln(connection, "after"); err != nil {
			return fmt.Errorf("notify probe completion: %w", err)
		}
	}
	return nil
}

func measureHelper(ctx context.Context, unit, executable, path string) (time.Duration, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := listener.(*net.TCPListener).SetDeadline(deadline); err != nil {
			return 0, err
		}
	}
	done := make(chan error, 1)
	go func() { done <- runHelper(ctx, unit, executable, path, listener.Addr().String()) }()
	connection, err := listener.Accept()
	if err != nil {
		return 0, fmt.Errorf("accept probe timing connection: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return 0, err
		}
	}
	var signal string
	if _, err := fmt.Fscanln(connection, &signal); err != nil {
		return 0, fmt.Errorf("read probe start: %w", err)
	}
	if signal != "before" {
		return 0, fmt.Errorf("unexpected probe start signal %q", signal)
	}
	started := time.Now()
	if _, err := fmt.Fscanln(connection, &signal); err != nil {
		return 0, fmt.Errorf("read probe completion: %w", err)
	}
	if signal != "after" {
		return 0, fmt.Errorf("unexpected probe completion signal %q", signal)
	}
	if err := waitForHelper(ctx, done); err != nil {
		return 0, err
	}
	return time.Since(started), nil
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

func waitForPrompt(ctx context.Context, messages <-chan *apiclient.Message, path string) (promptIdentity, error) {
	for {
		select {
		case message := <-messages:
			if isPromptFor(message, path) {
				return promptIdentityFromMessage(message)
			}
		case <-ctx.Done():
			return promptIdentity{}, fmt.Errorf("wait for prompt for %s: %w", path, ctx.Err())
		}
	}
}

func promptIdentityFromMessage(message *apiclient.Message) (promptIdentity, error) {
	var data struct {
		EventData struct {
			Profile struct {
				ID         string
				Source     string
				Name       string
				LinkedPath string
			}
			Subject struct {
				Exe string
				Op  string
			}
		}
	}
	if _, err := dsd.Load(message.RawValue, &data); err != nil {
		return promptIdentity{}, fmt.Errorf("decode prompt identity: %w", err)
	}
	if data.EventData.Profile.ID == "" && data.EventData.Subject.Exe == "" {
		return promptIdentity{}, errors.New("decode prompt identity: notification has no event identity")
	}
	return promptIdentity{Key: message.Key, Identity: helperIdentity{
		ProfileSource: data.EventData.Profile.Source,
		ProfileID:     data.EventData.Profile.ID,
		ProfileName:   data.EventData.Profile.Name,
		ProfilePath:   data.EventData.Profile.LinkedPath,
		Executable:    data.EventData.Subject.Exe,
		Operation:     data.EventData.Subject.Op,
	}}, nil
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

func waitForObservation(ctx context.Context, address, path string, minimum int) (helperIdentity, int, error) {
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/api/v1/filequery/query", strings.NewReader(`{"pageSize":20}`))
		if err != nil {
			return helperIdentity{}, 0, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			var payload struct {
				Results []struct {
					Path    string
					Exe     string
					Verdict string
					Profile string
					AppName string
				}
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			_ = response.Body.Close()
			if decodeErr == nil {
				count := 0
				for _, record := range payload.Results {
					if record.Path != path || record.Verdict != "allow" {
						continue
					}
					count++
					if count >= minimum {
						source, id, _ := strings.Cut(record.Profile, "/")
						return helperIdentity{ProfileSource: source, ProfileID: id, ProfileName: record.AppName, Executable: record.Exe}, count, nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return helperIdentity{}, 0, fmt.Errorf("wait for file observation: %w", ctx.Err())
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

func preparePrivateJSON(path string) (*os.File, error) {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func commitPrivateJSON(path string, file *os.File, data []byte) error {
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
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

func containerID() string {
	data, err := os.ReadFile("/run/.containerenv")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "id="); ok {
			return strings.Trim(value, "\"")
		}
	}
	return ""
}

func mountNamespace() string {
	value, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return "unknown"
	}
	return value
}

func isolatedMountNamespace() bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[4] != "/" {
			continue
		}
		for index, field := range fields {
			if field == "-" {
				for _, option := range fields[6:index] {
					if strings.HasPrefix(option, "shared:") || strings.HasPrefix(option, "master:") {
						return false
					}
				}
				return true
			}
		}
	}
	return false
}

func hasCapability(bit uint) bool {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		value, ok := strings.CutPrefix(line, "CapEff:\t")
		if !ok {
			continue
		}
		capabilities, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		return err == nil && capabilities&(uint64(1)<<bit) != 0
	}
	return false
}
