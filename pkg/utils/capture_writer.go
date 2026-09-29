package utils

import (
	"bytes"

	"github.com/projectdiscovery/gologger/levels"
)

// CaptureWriter captures log output for testing
type CaptureWriter struct {
	Buffer *bytes.Buffer
}

func (w *CaptureWriter) Write(data []byte, level levels.Level) {
	w.Buffer.Write(data)
}
