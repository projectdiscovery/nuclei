package ssrf

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerRegistered(t *testing.T) {
	require.NotNil(t, analyzers.GetAnalyzer("ssrf"))
	require.Equal(t, "ssrf", (&Analyzer{}).Name())
}

func TestMatchSSRFSignature(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantSvc string
		wantHit bool
	}{
		{
			name:    "aws instance identity document",
			body:    `{"accountId":"123456789012","imageId":"ami-0abcd1234ef567890","instanceId":"i-0abcd1234ef567890","region":"us-east-1"}`,
			wantSvc: "AWS instance identity document (IMDS)",
			wantHit: true,
		},
		{
			name:    "aws imds metadata listing",
			body:    "ami-id\nami-launch-index\nhostname\niam/\ninstance-action\ninstance-id\nlocal-hostname\n",
			wantSvc: "AWS IMDS metadata",
			wantHit: true,
		},
		{
			name:    "aws sts credentials",
			body:    `{"Code":"Success","AccessKeyId":"ASIAEXAMPLE1234567890","SecretAccessKey":"x","Token":"y"}`,
			wantSvc: "AWS instance credentials (IMDS)",
			wantHit: true,
		},
		{
			name:    "gcp compute metadata recursive response",
			body:    `{"hostname":"vm.c.proj.internal","machineType":"projects/1/machineTypes/e2-medium","serviceAccounts":{"default":{"email":"x@developer.gserviceaccount.com"}}}`,
			wantSvc: "GCP instance metadata",
			wantHit: true,
		},
		{
			name:    "benign body no metadata",
			body:    `<html><body>welcome to the dashboard, instance-id of order is 5</body></html>`,
			wantHit: false,
		},
		{
			// Regression: an app that merely reflects the injected GCP payload URL
			// (which contains "computeMetadata") must NOT be flagged. Only a real
			// metadata *response* (structural JSON keys) counts.
			name:    "reflected gcp payload url is not a hit",
			body:    `<html><body>you searched for: http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true</body></html>`,
			wantHit: false,
		},
		{
			// Regression: reflected AWS metadata URL alone is not disclosure.
			name:    "reflected aws payload url is not a hit",
			body:    `<html><body>fetched http://169.254.169.254/latest/meta-data/ failed</body></html>`,
			wantHit: false,
		},
		{
			name:    "partial aws keys do not match identity doc",
			body:    `{"instanceId":"i-0abcd1234ef567890"}`,
			wantHit: false,
		},
		{
			name:    "empty body",
			body:    ``,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, hit := MatchSSRFSignature(tc.body)
			require.Equal(t, tc.wantHit, hit)
			if tc.wantHit {
				require.Equal(t, tc.wantSvc, svc)
			}
		})
	}
}

func TestMetadataPayloadsNonEmpty(t *testing.T) {
	require.NotEmpty(t, metadataPayloads)
	for _, p := range metadataPayloads {
		require.NotEmpty(t, p)
	}
}
