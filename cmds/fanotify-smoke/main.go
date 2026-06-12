// Phase-1 smoke test for the fileaccess module. Not part of the daemon;
// kept around as a focused way to exercise just the fanotify path.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/safing/portmaster/service/fileaccess"
)

type stubInstance struct{}

func main() {
	fa, err := fileaccess.New(stubInstance{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "new:", err)
		os.Exit(1)
	}
	if err := fa.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	fmt.Println("fanotify up; sleeping 5s (touch /tmp/filemaster-test/<anything> to fire an event)")
	time.Sleep(5 * time.Second)
	if err := fa.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
	}
	fmt.Println("done")
}
