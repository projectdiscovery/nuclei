package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/client/mocks"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestScans(t *testing.T) {
	setup := mocks.NewMockHttpServer(t)
	defer setup()
	client := New(WithToken("test"))
	svc := ScansService{Client: client}
	var scanID int64 = 0
	t.Run("AddScan", func(t *testing.T) {
		testserver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = w.Write([]byte("Example Domain"))
		}))
		defer testserver.Close()

		_ = protocolinit.Init(testutils.DefaultOptions)

		resp, err := svc.AddScan(AddScanRequest{
			Name:      "integration-test-scan",
			RunNow:    true,
			Targets:   []string{testserver.URL},
			Templates: []string{"http-add-scan-test.yaml"},
		})
		require.NoError(t, err, "could not add scan")
		require.Greater(t, resp, int64(0))
		scanID = resp
		time.Sleep(2 * time.Second)
	})

	t.Run("GetScans", func(t *testing.T) {
		resp, err := svc.GetScans(GetScansRequest{})
		require.NoError(t, err, "could not get scans")
		require.Greater(t, len(resp), 0)
	})
	t.Run("DeleteScan", func(t *testing.T) {
		err := svc.DeleteScan(scanID)
		require.NoError(t, err, "could not delete scan")
	})
	t.Run("ScanProgress", func(t *testing.T) {
		resp, err := svc.GetScanProgress()
		require.NoError(t, err, "could not get scan progress")
		require.GreaterOrEqual(t, len(resp), 0)
	})
	t.Run("GetScan", func(t *testing.T) {
		resp, err := svc.GetScan(scanID)
		require.NoError(t, err, "could not get scan")
		require.GreaterOrEqual(t, len(resp.Name), 0)
	})
	t.Run("GetScanMatches", func(t *testing.T) {
		resp, err := svc.GetScanMatches(GetScanMatchesRequest{ID: scanID})
		require.NoError(t, err, "could not get scan matches")
		require.GreaterOrEqual(t, len(resp), 0)
	})
	t.Run("GetScanErrors", func(t *testing.T) {
		resp, err := svc.GetScanErrors(scanID)
		require.NoError(t, err, "could not get scan errors")
		require.GreaterOrEqual(t, len(resp), 0)
	})
}
