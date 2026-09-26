// Baseline-guard tests for the baseline-diffing analyzers (sqli, lfi, ssrf,
// cmdi). Each of those analyzers first issues a request with the ORIGINAL value
// and bails out if the vulnerability signature is already present — otherwise a
// page that always shows e.g. a SQL error or a "uid=" string would be a false
// positive. These tests stand up servers that emit the signature
// UNCONDITIONALLY (even for the untouched original value) and assert the
// analyzer reports nothing.
package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSQLi_BaselineGuard_E2E(t *testing.T) {
	// Always returns a MySQL error, even for the benign original value.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax")
	}))
	defer srv.Close()

	matched, _ := run(t, "sqli_error", newGeneratedRequest(t, srv.URL, "q", "test"), newClient(true))
	require.False(t, matched, "sqli must not fire when the DBMS error is present in the baseline already")
}

func TestLFI_BaselineGuard_E2E(t *testing.T) {
	// Always returns /etc/passwd content regardless of the input.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
	}))
	defer srv.Close()

	matched, _ := run(t, "lfi", newGeneratedRequest(t, srv.URL, "q", "home.txt"), newClient(true))
	require.False(t, matched, "lfi must not fire when the file signature is present in the baseline already")
}

func TestSSRF_BaselineGuard_E2E(t *testing.T) {
	// Always returns the AWS instance identity document regardless of the input.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"accountId":"123456789012","imageId":"ami-0abcd1234ef567890","instanceId":"i-0abcd1234ef567890","region":"us-east-1"}`)
	}))
	defer srv.Close()

	matched, _ := run(t, "ssrf", newGeneratedRequest(t, srv.URL, "q", "https://example.com/a.png"), newClient(true))
	require.False(t, matched, "ssrf must not fire when the metadata signature is present in the baseline already")
}

func TestCMDi_BaselineGuard_E2E(t *testing.T) {
	// Always returns command output regardless of input (e.g. a page that
	// legitimately prints a "uid=" string).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "current identity: uid=0(root) gid=0(root) groups=0(root)")
	}))
	defer srv.Close()

	matched, _ := run(t, "cmdi", newGeneratedRequest(t, srv.URL, "q", "127.0.0.1"), newClient(true))
	require.False(t, matched, "cmdi must not fire when command output is present in the baseline already")
}
