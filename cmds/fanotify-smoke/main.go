// Phase-1 smoke test for the fileaccess module. Not part of the daemon;
// kept around as a focused way to exercise just the fanotify path.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safing/portmaster/service/fileaccess"
)

type stubInstance struct{}

func main() {
	var watchPaths []string
	for _, p := range strings.Split(os.Getenv("FM_WATCH_PATHS"), ":") {
		if p = strings.TrimSpace(p); p != "" {
			watchPaths = append(watchPaths, p)
		}
	}
	if len(watchPaths) == 0 {
		fmt.Fprintln(os.Stderr, "set FM_WATCH_PATHS to the directories to watch")
		os.Exit(2)
	}

	fa, err := fileaccess.New(stubInstance{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "new:", err)
		os.Exit(1)
	}
	if err := fa.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	fmt.Printf("fanotify up for %s; sleeping 5s\n", strings.Join(watchPaths, ":"))
	time.Sleep(5 * time.Second)
	if err := fa.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
	}
	fmt.Println("done")
}
