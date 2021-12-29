package scans

import (
	"bufio"
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/stretchr/testify/require"
)

func TestWrappedOutputWriter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tempdir, err := ioutil.TempDir("", "test-data-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempdir)

	logsStorage := NewErrorLogsService(tempdir)
	querier := db.NewMockQuerier(ctrl)
	scanID := int64(12)

	writer, err := logsStorage.Write(scanID)
	require.NoError(t, err, "could not write log file")

	bufwriter := bufio.NewWriter(writer)
	wrappedOutputWriter := newWrappedOutputWriter(querier, bufwriter, scanID, "")

	t.Run("result", func(t *testing.T) {
		querier.EXPECT().
			AddIssue(gomock.Any(), gomock.Any()).
			Times(1).
			Return(int64(1), nil)

		err := wrappedOutputWriter.Write(&output.ResultEvent{
			TemplatePath: "worker_output_test.go",
		})
		require.NoError(t, err, "could not write output event")
	})

	t.Run("error", func(t *testing.T) {
		templateID := "test-template"
		url := "https://example.com"
		requestType := "dns"
		gotError := errors.New("could not resolve: NXDOMAIN")

		wrappedOutputWriter.Request(templateID, url, requestType, gotError)
		bufwriter.Flush()
		writer.Close()

		reader, err := logsStorage.Read(scanID)
		require.NoError(t, err, "could not read scan error log")

		data, _ := ioutil.ReadAll(reader)
		var expected bytes.Buffer
		_ = jsoniter.NewEncoder(&expected).Encode(ScanErrorLogEvent{
			Template: templateID,
			URL:      url,
			Type:     requestType,
			Error:    gotError.Error(),
		})
		require.Equal(t, expected.Bytes(), data, "could not get correct response")
	})
}
