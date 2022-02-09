package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScans(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	var scanID int64 = 0
	t.Run("AddScan", func(t *testing.T) {
		resp, err := svc.AddScan(AddScanRequest{
			Name:      "integration-test-scan",
			RunNow:    true,
			Targets:   []string{"example.com", "wordpress.com"},
			Templates: []string{"workflows/zimbra-workflow.yaml", "CVE-2000-0116.yaml"},
		})
		require.NoError(t, err, "could not add scan")
		require.Greater(t, resp, int64(0))
		scanID = resp
	})

	t.Run("GetScans", func(t *testing.T) {
		resp, err := svc.GetScans(GetScansRequest{
			Search: "scans.txt",
		})
		fmt.Println(resp)
		require.NoError(t, err, "could not get scans")
	})
	t.Run("UpdateScan", func(t *testing.T) {
		err := svc.UpdateScan(scanID, UpdateScanRequest{
			Stop: false,
		})
		require.NoError(t, err, "could not add scan")
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
		resp, err := svc.GetScans(GetScansRequest{
			Search: "scan.txt",
		})
		require.NoError(t, err, "could not add scan")
		require.GreaterOrEqual(t, len(resp), 0)
	})
	t.Run("ExecuteScan", func(t *testing.T) {
		err := svc.ExecuteScan(scanID)
		require.NoError(t, err, "could not execute scan")
	})
	t.Run("GetScanMatches", func(t *testing.T) {
		resp, err := svc.GetScanMatches(scanID)
		require.NoError(t, err, "could not execute scan")
		require.GreaterOrEqual(t, len(resp), 0)
	})
	t.Run("GetScanErrors", func(t *testing.T) {
		resp, err := svc.GetScanErrors(scanID)
		require.NoError(t, err, "could not execute scan")
		require.GreaterOrEqual(t, len(resp), 0)
	})
}
