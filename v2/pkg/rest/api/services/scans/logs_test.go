package scans

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanErrorLogService(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "test-data-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempdir)

	service := NewErrorLogsService(tempdir)
	writer, err := service.Write(1)
	require.NoError(t, err, "could not write logs")

	_, err = writer.Write([]byte("testdata"))
	require.NoError(t, err, "could not write logs to file")
	_ = writer.Close()

	reader, err := service.Read(1)
	require.NoError(t, err, "could not read log file")

	data, err := ioutil.ReadAll(reader)
	_ = reader.Close()
	require.NoError(t, err, "could not read log data")
	require.Equal(t, "testdata", string(data), "could not get correct data")
}
