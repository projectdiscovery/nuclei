package pdcp

import (
	"bytes"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestSetScanIDWarnsOnWriterLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := &gologger.Logger{}
	logger.SetWriter(&utils.CaptureWriter{Buffer: &buf})
	logger.SetFormatter(formatter.NewCLI(true))
	logger.SetMaxLevel(levels.LevelWarning)

	u := &UploadWriter{Logger: logger}
	require.NoError(t, u.SetScanID("invalid-id"))
	require.Equal(t, "invalid-id", u.scanID)
	require.Contains(t, buf.String(), "invalid asset id provided (unknown xid format): invalid-id")

	// a valid xid doesn't log anything
	buf.Reset()
	require.NoError(t, u.SetScanID("abcdefghij0123456789"))
	require.Empty(t, buf.String())
}
