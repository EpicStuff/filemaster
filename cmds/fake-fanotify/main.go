// fake-fanotify sends synthetic file-access events to a running filemaster
// daemon over a Unix socket and prints the verdict for each one.
//
// Usage:
//
//	FM_FAKE_SOCKET=/tmp/fake.sock ./portmaster-core &
//	echo '{"pid":1,"exe":"/usr/bin/cat","path":"/etc/passwd","op":"open"}' | fake-fanotify -socket /tmp/fake.sock
//
// One JSON object per stdin line; blank lines and lines starting with # are
// skipped. The daemon must be started with FM_FAKE_SOCKET set to the same path.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	socket := flag.String("socket", os.Getenv("FM_FAKE_SOCKET"), "Unix socket path (or set FM_FAKE_SOCKET)")
	flag.Parse()

	if *socket == "" {
		fmt.Fprintln(os.Stderr, "fake-fanotify: set -socket or FM_FAKE_SOCKET")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", *socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake-fanotify: connect %s: %v\n", *socket, err)
		os.Exit(1)
	}
	defer conn.Close()

	in := bufio.NewScanner(os.Stdin)
	verdicts := bufio.NewScanner(conn)

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
			fmt.Fprintf(os.Stderr, "fake-fanotify: send: %v\n", err)
			os.Exit(1)
		}
		if !verdicts.Scan() {
			fmt.Fprintln(os.Stderr, "fake-fanotify: connection closed by daemon")
			os.Exit(1)
		}
		fmt.Printf("%s → %s\n", line, verdicts.Text())
	}
}
