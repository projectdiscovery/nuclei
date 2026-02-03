package types

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestProfileMetadataFields tests that profile metadata fields can be parsed
// without causing errors (Feature 1 from #5567)
func TestProfileMetadataFields(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected Options
	}{
		{
			name: "all metadata fields",
			yaml: `
id: test-profile
name: Test Profile
purpose: Security scanning
description: A test profile for security scanning
`,
			expected: Options{
				ProfileID:          "test-profile",
				ProfileName:        "Test Profile",
				ProfilePurpose:     "Security scanning",
				ProfileDescription: "A test profile for security scanning",
			},
		},
		{
			name: "partial metadata fields",
			yaml: `
id: partial-profile
name: Partial Test
`,
			expected: Options{
				ProfileID:   "partial-profile",
				ProfileName: "Partial Test",
			},
		},
		{
			name: "metadata with other options",
			yaml: `
id: combined-profile
name: Combined Profile
purpose: Full scan
timeout: 30
`,
			expected: Options{
				ProfileID:      "combined-profile",
				ProfileName:    "Combined Profile",
				ProfilePurpose: "Full scan",
				Timeout:        30,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts Options
			err := yaml.Unmarshal([]byte(tc.yaml), &opts)
			require.NoError(t, err, "should parse profile metadata without errors")
			require.Equal(t, tc.expected.ProfileID, opts.ProfileID)
			require.Equal(t, tc.expected.ProfileName, opts.ProfileName)
			require.Equal(t, tc.expected.ProfilePurpose, opts.ProfilePurpose)
			require.Equal(t, tc.expected.ProfileDescription, opts.ProfileDescription)
		})
	}
}

// TestInlineTargetsList tests that inline target lists can be parsed
// from YAML multiline syntax (Feature 2 from #5567)
func TestInlineTargetsList(t *testing.T) {
	tests := []struct {
		name            string
		yaml            string
		expectedTargets string
	}{
		{
			name: "multiline targets",
			yaml: `
list: |
  example.com
  test.com
  api.example.com
`,
			expectedTargets: "example.com\ntest.com\napi.example.com\n",
		},
		{
			name: "single target",
			yaml: `
list: |
  single.example.com
`,
			expectedTargets: "single.example.com\n",
		},
		{
			name: "targets with urls",
			yaml: `
list: |
  https://example.com/path
  http://test.com:8080
  ftp://files.example.com
`,
			expectedTargets: "https://example.com/path\nhttp://test.com:8080\nftp://files.example.com\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts Options
			err := yaml.Unmarshal([]byte(tc.yaml), &opts)
			require.NoError(t, err, "should parse inline targets without errors")
			require.Equal(t, tc.expectedTargets, opts.TargetsInline)
		})
	}
}

// TestInlineSecretsConfig tests that inline secrets can be parsed
// from profile YAML (Feature 3 from #5567)
func TestInlineSecretsConfig(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		hasError bool
	}{
		{
			name: "static header auth",
			yaml: `
secrets:
  static:
    - type: header
      domains:
        - api.example.com
      headers:
        - key: x-api-key
          value: secret-key
`,
			hasError: false,
		},
		{
			name: "static basic auth",
			yaml: `
secrets:
  static:
    - type: basicauth
      domains:
        - secure.example.com
      username: admin
      password: secret123
`,
			hasError: false,
		},
		{
			name: "dynamic auth with template",
			yaml: `
secrets:
  dynamic:
    - template: oauth-flow.yaml
      variables:
        - name: username
          value: testuser
        - name: password
          value: testpass
`,
			hasError: false,
		},
		{
			name: "combined static and dynamic",
			yaml: `
secrets:
  static:
    - type: header
      domains:
        - api.example.com
      headers:
        - key: Authorization
          value: Bearer static-token
  dynamic:
    - template: oauth.yaml
      variables:
        - name: client_id
          value: my-client
`,
			hasError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts Options
			err := yaml.Unmarshal([]byte(tc.yaml), &opts)
			if tc.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "should parse inline secrets without errors")
				require.NotNil(t, opts.InlineSecrets, "InlineSecrets should not be nil")
			}
		})
	}
}

// TestCompleteProfileParsing tests that all features work together
// in a single complete profile YAML
func TestCompleteProfileParsing(t *testing.T) {
	completeProfile := `
# Profile metadata (Feature 1)
id: projectdiscovery-scan
name: ProjectDiscovery Infrastructure Scan
purpose: Security assessment of PD infrastructure
description: Complete configuration for scanning ProjectDiscovery targets

# Inline targets (Feature 2)
list: |
  cve.projectdiscovery.io
  chaos.projectdiscovery.io
  api.projectdiscovery.io

# Standard nuclei options
timeout: 30
retries: 2

# Inline secrets (Feature 3)
secrets:
  static:
    - type: header
      domains:
        - api.projectdiscovery.io
      headers:
        - key: x-pdcp-key
          value: test-api-key
  dynamic:
    - template: oauth-flow.yaml
      variables:
        - name: username
          value: pdteam
        - name: password
          value: secret
`

	var opts Options
	err := yaml.Unmarshal([]byte(completeProfile), &opts)
	require.NoError(t, err, "should parse complete profile without errors")

	// Verify metadata
	require.Equal(t, "projectdiscovery-scan", opts.ProfileID)
	require.Equal(t, "ProjectDiscovery Infrastructure Scan", opts.ProfileName)
	require.Equal(t, "Security assessment of PD infrastructure", opts.ProfilePurpose)
	require.Contains(t, opts.ProfileDescription, "Complete configuration")

	// Verify inline targets
	require.NotEmpty(t, opts.TargetsInline)
	require.Contains(t, opts.TargetsInline, "cve.projectdiscovery.io")
	require.Contains(t, opts.TargetsInline, "chaos.projectdiscovery.io")
	require.Contains(t, opts.TargetsInline, "api.projectdiscovery.io")

	// Verify standard options
	require.Equal(t, 30, opts.Timeout)
	require.Equal(t, 2, opts.Retries)

	// Verify inline secrets
	require.NotNil(t, opts.InlineSecrets)
	require.Len(t, opts.InlineSecrets.Static, 1)
	require.Len(t, opts.InlineSecrets.Dynamic, 1)
}

// TestOptionsCopyIncludesProfileFields tests that Options.Copy() correctly
// copies all new profile-related fields (critical bug fix over PR #6804)
func TestOptionsCopyIncludesProfileFields(t *testing.T) {
	original := &Options{
		ProfileID:          "test-id",
		ProfileName:        "Test Name",
		ProfilePurpose:     "Testing",
		ProfileDescription: "Test Description",
		TargetsInline:      "example.com\ntest.com\n",
		InlineSecrets: &InlineSecretsConfig{
			Static: []map[string]interface{}{
				{"type": "header", "domains": []string{"example.com"}},
			},
		},
		Timeout: 30,
	}

	copied := original.Copy()

	// Verify all profile fields are copied
	require.Equal(t, original.ProfileID, copied.ProfileID, "ProfileID should be copied")
	require.Equal(t, original.ProfileName, copied.ProfileName, "ProfileName should be copied")
	require.Equal(t, original.ProfilePurpose, copied.ProfilePurpose, "ProfilePurpose should be copied")
	require.Equal(t, original.ProfileDescription, copied.ProfileDescription, "ProfileDescription should be copied")
	require.Equal(t, original.TargetsInline, copied.TargetsInline, "TargetsInline should be copied")
	require.Equal(t, original.InlineSecrets, copied.InlineSecrets, "InlineSecrets should be copied")

	// Verify standard field is also copied
	require.Equal(t, original.Timeout, copied.Timeout, "Timeout should be copied")
}
