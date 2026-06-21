package log

import (
	"fmt"
	"os"
)

// GlobalWriter is the global log writer.
var GlobalWriter *LogWriter = nil

type LogWriter struct {
	file *os.File
}

// NewStdoutWriter creates a new log writer that writes to stdout.
func NewStdoutWriter() *LogWriter {
	return &LogWriter{
		file: os.Stdout,
	}
}

// Write writes the buffer to the writer.
func (l *LogWriter) Write(buf []byte) (int, error) {
	if l == nil {
		return 0, fmt.Errorf("log writer not initialized")
	}
	return l.file.Write(buf)
}

// WriteMessage writes the message to the writer.
func (l *LogWriter) WriteMessage(msg Message, duplicates uint64) {
	if l == nil {
		return
	}
	fmt.Fprintln(l.file, formatLine(msg.(*logLine), duplicates, true))
}

// IsStdout returns true; filemaster only ever logs to stdout.
func (l *LogWriter) IsStdout() bool {
	return l != nil
}

// Close is a no-op; we never close stdout.
func (l *LogWriter) Close() {}
