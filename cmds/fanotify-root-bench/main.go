// fanotify-root-bench measures the transport cost of a temporary mount mark on /.
// It intentionally has no Filemaster policy, persistence, logging, or prompts.
//
// The -mask flag selects the permission mask: "open" (the default, matching the
// mask filemaster marks without the interceptReads option), "read"
// (FAN_ACCESS_PERM alone), or "both". read/both fire one blocking permission
// event per read() syscall across the entire marked mount, so on a busy system
// they can stall every reader until this process responds — use a short timeout.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type mode string

const (
	raw        mode = "raw"
	classified mode = "classified"
)

type sample struct {
	fd       int32
	received time.Time
}

type histogram struct {
	LE10us  uint64 `json:"le_10us"`
	LE25us  uint64 `json:"le_25us"`
	LE50us  uint64 `json:"le_50us"`
	LE100us uint64 `json:"le_100us"`
	LE250us uint64 `json:"le_250us"`
	LE500us uint64 `json:"le_500us"`
	LE1ms   uint64 `json:"le_1ms"`
	LE5ms   uint64 `json:"le_5ms"`
	LE10ms  uint64 `json:"le_10ms"`
	GT10ms  uint64 `json:"gt_10ms"`
}

func (h *histogram) add(d time.Duration) {
	switch {
	case d <= 10*time.Microsecond:
		h.LE10us++
	case d <= 25*time.Microsecond:
		h.LE25us++
	case d <= 50*time.Microsecond:
		h.LE50us++
	case d <= 100*time.Microsecond:
		h.LE100us++
	case d <= 250*time.Microsecond:
		h.LE250us++
	case d <= 500*time.Microsecond:
		h.LE500us++
	case d <= time.Millisecond:
		h.LE1ms++
	case d <= 5*time.Millisecond:
		h.LE5ms++
	case d <= 10*time.Millisecond:
		h.LE10ms++
	default:
		h.GT10ms++
	}
}

type result struct {
	Mode              mode      `json:"mode"`
	Mask              string    `json:"mask"`
	Workers           int       `json:"workers"`
	Scope             string    `json:"scope"`
	Command           []string  `json:"command"`
	WallMS            float64   `json:"wall_ms"`
	WatchWindowMS     float64   `json:"watch_window_ms"`
	UserCPUms         float64   `json:"user_cpu_ms"`
	SystemCPUms       float64   `json:"system_cpu_ms"`
	Events            uint64    `json:"events"`
	EventRate         float64   `json:"event_rate_per_sec"`
	Overflows         uint64    `json:"overflows"`
	ResponseErrors    uint64    `json:"response_errors"`
	WorkerUtilization float64   `json:"worker_utilization_percent"`
	Latency           histogram `json:"read_to_response_latency_us"`
	TimedOut          bool      `json:"timed_out"`
	Failure           string    `json:"failure,omitempty"`
}

func response(fd, eventFD int32) error {
	resp := unix.FanotifyResponse{Fd: eventFD, Response: unix.FAN_ALLOW}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(&resp)), unsafe.Sizeof(resp))
	for {
		_, err := unix.Write(int(fd), bytes)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			_, err = unix.Poll([]unix.PollFd{{Fd: fd, Events: unix.POLLOUT}}, 100)
			if err == nil || errors.Is(err, unix.EINTR) {
				continue
			}
		}
		return err
	}
}

func benchmark(runMode mode, maskName string, mask uint64, workers int, scope string, timeout time.Duration, dir string, command []string) result {
	res := result{Mode: runMode, Mask: maskName, Workers: workers, Scope: scope, Command: command}
	started := time.Now()
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
	if err != nil {
		res.Failure = fmt.Sprintf("fanotify_init: %v", err)
		return res
	}
	defer unix.Close(fd)

	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, "/"); err != nil {
		res.Failure = fmt.Sprintf("fanotify_mark /: %v", err)
		return res
	}
	marked := true
	defer func() {
		if marked {
			_ = unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, "/")
		}
	}()

	jobs := make(chan sample, 32768)
	stop := make(chan struct{})
	var reader sync.WaitGroup
	var worker sync.WaitGroup
	var events, overflows, responseErrors, busyNS atomic.Uint64
	var latency histogram
	var latencyMu sync.Mutex

	for range workers {
		worker.Add(1)
		go func() {
			defer worker.Done()
			for event := range jobs {
				workStarted := time.Now()
				if runMode == classified {
					path, readlinkErr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", event.fd))
					if readlinkErr == nil {
						_ = path == scope || strings.HasPrefix(path, scope+string(os.PathSeparator))
					}
				}
				if err := response(int32(fd), event.fd); err != nil {
					responseErrors.Add(1)
				}
				_ = unix.Close(int(event.fd))
				busyNS.Add(uint64(time.Since(workStarted)))
				latencyMu.Lock()
				latency.add(time.Since(event.received))
				latencyMu.Unlock()
			}
		}()
	}

	reader.Add(1)
	go func() {
		defer reader.Done()
		defer close(jobs)
		buf := make([]byte, 64*1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, readErr := unix.Read(fd, buf)
			if readErr != nil {
				if errors.Is(readErr, unix.EINTR) {
					continue
				}
				if errors.Is(readErr, unix.EAGAIN) {
					_, _ = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 25)
					continue
				}
				return
			}
			for offset := 0; offset+int(unsafe.Sizeof(unix.FanotifyEventMetadata{})) <= n; {
				meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
				if meta.Event_len < uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{})) || offset+int(meta.Event_len) > n {
					return
				}
				offset += int(meta.Event_len)
				if meta.Mask&unix.FAN_Q_OVERFLOW != 0 {
					overflows.Add(1)
					continue
				}
				if meta.Fd < 0 {
					continue
				}
				events.Add(1)
				select {
				case jobs <- sample{fd: meta.Fd, received: time.Now()}:
				case <-stop:
					_ = unix.Close(int(meta.Fd))
					return
				}
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CHROME_CRASHPAD_PIPE_NAME=/tmp/fanotify-root-bench-crashpad")
	workloadStarted := time.Now()
	err = cmd.Run()
	res.WallMS = float64(time.Since(workloadStarted).Microseconds()) / 1000
	res.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if err != nil && !res.TimedOut {
		res.Failure = fmt.Sprintf("workload: %v", err)
	}
	if cmd.ProcessState != nil {
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			res.UserCPUms = float64(usage.Utime.Sec)*1000 + float64(usage.Utime.Usec)/1000
			res.SystemCPUms = float64(usage.Stime.Sec)*1000 + float64(usage.Stime.Usec)/1000
		}
	}

	// Stop new events first, then give queued permission events a bounded drain window.
	_ = unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT, mask, unix.AT_FDCWD, "/")
	marked = false
	time.Sleep(100 * time.Millisecond)
	close(stop)
	reader.Wait()
	worker.Wait()

	res.WatchWindowMS = float64(time.Since(started).Microseconds()) / 1000
	res.Events = events.Load()
	res.Overflows = overflows.Load()
	res.ResponseErrors = responseErrors.Load()
	res.Latency = latency
	if res.WatchWindowMS > 0 {
		res.EventRate = float64(res.Events) / (res.WatchWindowMS / 1000)
		res.WorkerUtilization = float64(busyNS.Load()) / float64(time.Duration(res.WatchWindowMS*float64(time.Millisecond))*time.Duration(workers)) * 100
	}
	if res.Overflows > 0 && res.Failure == "" {
		res.Failure = "fanotify queue overflow"
	}
	if res.ResponseErrors > 0 && res.Failure == "" {
		res.Failure = "fanotify response errors"
	}
	return res
}

func runBaseline(timeout time.Duration, dir string, command []string) result {
	res := result{Mode: "baseline", Workers: 0, Command: command}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CHROME_CRASHPAD_PIPE_NAME=/tmp/fanotify-root-bench-crashpad")
	started := time.Now()
	err := cmd.Run()
	res.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if err != nil && !res.TimedOut {
		res.Failure = fmt.Sprintf("workload: %v", err)
	}
	if cmd.ProcessState != nil {
		if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
			res.UserCPUms = float64(usage.Utime.Sec)*1000 + float64(usage.Utime.Usec)/1000
			res.SystemCPUms = float64(usage.Stime.Sec)*1000 + float64(usage.Stime.Usec)/1000
		}
	}
	res.WallMS = float64(time.Since(started).Microseconds()) / 1000
	return res
}

func storm(workers, iterations int) error {
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				file, err := os.Open("/etc/hosts")
				if err != nil {
					return
				}
				_ = file.Close()
				if err := exec.Command("/usr/bin/true").Run(); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "storm" {
		flags := flag.NewFlagSet("storm", flag.ExitOnError)
		workers := flags.Int("workers", 24, "parallel storm workers")
		iterations := flags.Int("iterations", 100, "open/exec pairs per worker")
		_ = flags.Parse(os.Args[2:])
		if err := storm(*workers, *iterations); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	flags := flag.NewFlagSet("fanotify-root-bench", flag.ExitOnError)
	runMode := flags.String("mode", "baseline", "baseline, raw, or classified")
	maskName := flags.String("mask", "open", "permission mask: open (FAN_OPEN_PERM|FAN_OPEN_EXEC_PERM), read (FAN_ACCESS_PERM, one event per read() syscall), or both. read/both fire per read() across the whole marked mount and can stall a busy system.")
	workers := flags.Int("workers", 1, "response workers")
	scope := flags.String("scope", "/root/filemaster", "classified in-scope path prefix")
	timeout := flags.Duration("timeout", 2*time.Minute, "hard workload timeout")
	dir := flags.String("dir", ".", "workload directory")
	_ = flags.Parse(os.Args[1:])
	command := flags.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fanotify-root-bench [flags] -- command [args...]")
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "fanotify mount benchmark needs root")
		os.Exit(2)
	}
	if *runMode != "baseline" && os.Getenv("FM_ROOT_BENCHMARK_ACK") != "I_UNDERSTAND_ROOT_MARKING" {
		fmt.Fprintln(os.Stderr, "refusing to mark / without FM_ROOT_BENCHMARK_ACK=I_UNDERSTAND_ROOT_MARKING")
		os.Exit(2)
	}

	var mask uint64
	switch *maskName {
	case "open":
		mask = uint64(unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM)
	case "read":
		mask = uint64(unix.FAN_ACCESS_PERM)
	case "both":
		mask = uint64(unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM | unix.FAN_ACCESS_PERM)
	default:
		fmt.Fprintln(os.Stderr, "mask must be open, read, or both")
		os.Exit(2)
	}

	var res result
	if *runMode == "baseline" {
		res = runBaseline(*timeout, *dir, command)
	} else if mode(*runMode) == raw || mode(*runMode) == classified {
		if *workers < 1 {
			fmt.Fprintln(os.Stderr, "workers must be positive")
			os.Exit(2)
		}
		res = benchmark(mode(*runMode), *maskName, mask, *workers, *scope, *timeout, *dir, command)
	} else {
		fmt.Fprintln(os.Stderr, "mode must be baseline, raw, or classified")
		os.Exit(2)
	}
	encoded, _ := json.Marshal(res)
	fmt.Println(string(encoded))
	if res.Failure != "" || res.TimedOut || res.Overflows > 0 {
		os.Exit(1)
	}
}
