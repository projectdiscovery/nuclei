package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetScans(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	resp, err := svc.GetScans(GetScansRequest{
		Search: "scans.txt",
	})
	fmt.Println(resp)
	require.NoError(t, err, "could not get scans")
}

func TestAddScan(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	resp, err := svc.AddScan(AddScanRequest{
		Name:      "integration-test-scan",
		RunNow:    true,
		Targets:   []string{"example.com", "wordpress.com"},
		Templates: []string{"workflows/zimbra-workflow.yaml", "CVE-2000-0116.yaml"},
	})
	require.NoError(t, err, "could not add scan")
	require.Greater(t, resp, int64(0))

}

func TestUpdateScan(t *testing.T) {
	//update scan takes two parameters
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	err := svc.UpdateScan(1, UpdateScanRequest{
		Stop: true,
	})
	require.NoError(t, err, "could not add scan")

}

func TestDeleteScan(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	err := svc.DeleteScan(1)
	require.NoError(t, err, "could not delete scan")

}

func TestGetScanProgress(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	resp, err := svc.GetScanProgress()
	require.NoError(t, err, "could not get scan progress")
	require.GreaterOrEqual(t, len(resp), 0)
}

func TestGetScan(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	resp, err := svc.GetScans(GetScansRequest{
		Search: "scan.txt",
	})
	require.NoError(t, err, "could not add scan")
	require.GreaterOrEqual(t, len(resp), 0)
}

func TestExecuteScan(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	err := svc.ExecuteScan(1)
	require.NoError(t, err, "could not execute scan")
}

func TestGetScanMatches(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	resp, err := svc.GetScanMatches(1)
	require.NoError(t, err, "could not execute scan")
	require.GreaterOrEqual(t, len(resp), 0)
}

func TestGetScanErrors(t *testing.T) {
	client := New(WithBasicAuth("user", "pass"))
	svc := ScansService{Client: client}
	resp, err := svc.GetScanErrors(1)
	require.NoError(t, err, "could not execute scan")
	require.GreaterOrEqual(t, len(resp), 0)

}
