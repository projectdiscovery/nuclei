package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantID      string
		wantName    string
		wantDesc    string
		wantPurpose string
		wantAuthor  string
		wantTags    int
		wantRawKeys []string
		wantErr     bool
	}{
		{
			name: "basic profile with metadata",
			content: `id: test-profile
name: Test Profile
description: A test profile
purpose: Testing
author: test-author
version: "1.0"
tags:
  - kev
  - cve`,
			wantID:      "test-profile",
			wantName:    "Test Profile",
			wantDesc:    "A test profile",
			wantPurpose: "Testing",
			wantAuthor:  "test-author",
			wantRawKeys: []string{"tags"},
			wantErr:     false,
		},
		{
			name: "profile without metadata",
			content: `tags:
  - kev
severity:
  - critical`,
			wantRawKeys: []string{"tags", "severity"},
			wantErr:     false,
		},
		{
			name: "profile with profile-tags",
			content: `id: test-profile
profile-tags:
  - internal
  - test
tags:
  - kev`,
			wantID:      "test-profile",
			wantTags:    2,
			wantRawKeys: []string{"tags"},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := ParseProfile([]byte(tt.content))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, profile)

			if tt.wantID != "" {
				require.Equal(t, tt.wantID, profile.ID)
			}
			if tt.wantName != "" {
				require.Equal(t, tt.wantName, profile.Name)
			}
			if tt.wantDesc != "" {
				require.Equal(t, tt.wantDesc, profile.Description)
			}
			if tt.wantPurpose != "" {
				require.Equal(t, tt.wantPurpose, profile.Purpose)
			}
			if tt.wantAuthor != "" {
				require.Equal(t, tt.wantAuthor, profile.Author)
			}
			if tt.wantTags > 0 {
				require.Len(t, profile.Tags, tt.wantTags)
			}

			for _, key := range tt.wantRawKeys {
				_, ok := profile.RawConfig[key]
				require.True(t, ok, "expected key %s in RawConfig", key)
			}
		})
	}
}

func TestProfileWithEmbeddedSecrets(t *testing.T) {
	content := `id: test-profile
name: Test Profile with Secrets
description: A test profile with embedded secrets
secrets:
  static:
    - type: Header
      domains:
        - example.com
      headers:
        - key: X-API-Key
          value: test-api-key
    - type: BasicAuth
      domains:
        - api.example.com
      username: admin
      password: password123
tags:
  - kev`

	profile, err := ParseProfile([]byte(content))
	require.NoError(t, err)
	require.NotNil(t, profile)

	require.True(t, profile.HasSecrets())
	require.NotNil(t, profile.Secrets)
	require.Len(t, profile.Secrets.Static, 2)

	// Verify first secret (Header auth)
	require.Equal(t, "Header", profile.Secrets.Static[0].Type)
	require.Equal(t, []string{"example.com"}, profile.Secrets.Static[0].Domains)
	require.Len(t, profile.Secrets.Static[0].Headers, 1)
	require.Equal(t, "X-API-Key", profile.Secrets.Static[0].Headers[0].Key)

	// Verify second secret (BasicAuth)
	require.Equal(t, "BasicAuth", profile.Secrets.Static[1].Type)
	require.Equal(t, "admin", profile.Secrets.Static[1].Username)

	// Verify GetAuthx
	authx := profile.GetAuthx()
	require.NotNil(t, authx)
	require.Equal(t, "test-profile", authx.ID)
	require.Len(t, authx.Secrets, 2)
}

func TestProfileWithoutSecrets(t *testing.T) {
	content := `id: test-profile
name: Test Profile
tags:
  - kev`

	profile, err := ParseProfile([]byte(content))
	require.NoError(t, err)
	require.NotNil(t, profile)

	require.False(t, profile.HasSecrets())
	require.Nil(t, profile.GetAuthx())
}

func TestProfileGetInfo(t *testing.T) {
	content := `id: test-profile
name: Test Profile
description: A test description
purpose: Testing
author: test-author
version: "1.0"
profile-tags:
  - tag1
  - tag2`

	profile, err := ParseProfile([]byte(content))
	require.NoError(t, err)

	info := profile.GetInfo()
	require.Equal(t, "test-profile", info.ID)
	require.Equal(t, "Test Profile", info.Name)
	require.Equal(t, "A test description", info.Description)
	require.Equal(t, "Testing", info.Purpose)
	require.Equal(t, "test-author", info.Author)
	require.Equal(t, "1.0", info.Version)
	require.Len(t, info.Tags, 2)
}

func TestWriteConfigForGoflags(t *testing.T) {
	content := `id: test-profile
name: Test Profile
description: A test description
tags:
  - kev
concurrency: 10`

	profile, err := ParseProfile([]byte(content))
	require.NoError(t, err)

	tmpDir := t.TempDir()
	configPath, err := profile.WriteConfigForGoflags(tmpDir)
	require.NoError(t, err)
	require.NotEmpty(t, configPath)

	// Verify file was created and contains only goflags-compatible fields
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	dataStr := string(data)
	require.Contains(t, dataStr, "tags")
	require.Contains(t, dataStr, "concurrency")
	require.NotContains(t, dataStr, "id:")
	require.NotContains(t, dataStr, "name:")
	require.NotContains(t, dataStr, "description:")

	// Clean up
	os.Remove(configPath)
}

func TestLoadProfileFromFile(t *testing.T) {
	content := `id: test-profile
name: Test Profile
tags:
  - kev`

	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "test-profile.yaml")
	err := os.WriteFile(profilePath, []byte(content), 0644)
	require.NoError(t, err)

	profile, err := LoadProfile(profilePath)
	require.NoError(t, err)
	require.NotNil(t, profile)
	require.Equal(t, "test-profile", profile.ID)
}

func TestLoadProfileInvalidExtension(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "test-profile.json")
	err := os.WriteFile(profilePath, []byte(`{"id": "test"}`), 0644)
	require.NoError(t, err)

	_, err = LoadProfile(profilePath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid file extension")
}

func TestValidateSecrets(t *testing.T) {
	// Valid secrets
	validContent := `id: test
secrets:
  static:
    - type: Header
      domains:
        - example.com
      headers:
        - key: X-API-Key
          value: test`

	profile, err := ParseProfile([]byte(validContent))
	require.NoError(t, err)
	require.NoError(t, profile.ValidateSecrets())

	// Invalid secrets (missing domains)
	invalidContent := `id: test
secrets:
  static:
    - type: Header
      headers:
        - key: X-API-Key
          value: test`

	profile, err = ParseProfile([]byte(invalidContent))
	require.NoError(t, err)
	require.Error(t, profile.ValidateSecrets())
}