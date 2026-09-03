package authx

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores/yaml"
	"github.com/getsops/sops/v3/version"
	"github.com/stretchr/testify/require"
)

func TestSecretsUnmarshal(t *testing.T) {
	data, err := GetAuthDataFromFile("testData/example-auth.yaml")
	require.NoError(t, err, "could not read secrets file")
	require.NotNil(t, data, "could not read secrets file")

	t.Run("encrypted", func(t *testing.T) {
		loc := encryptAuthFile(t, "testData/example-auth.yaml")
		decryptedData, err := GetAuthDataFromFile(loc)
		require.NoError(t, err, "could not read encrypted secrets file")
		require.NotNil(t, decryptedData, "could not read secrets file")
		require.Equal(t, data, decryptedData, "decrypted data should match original data")

		for _, s := range decryptedData.Secrets {
			require.NoError(t, s.Validate(), "could not validate secret")
		}

		for _, d := range decryptedData.Dynamic {
			require.NoError(t, d.Validate(), "could not validate dynamic")
		}
	})

	for _, s := range data.Secrets {
		require.NoError(t, s.Validate(), "could not validate secret")
	}

	for _, d := range data.Dynamic {
		require.NoError(t, d.Validate(), "could not validate dynamic")
	}
}

func encryptAuthFile(t *testing.T, source string) string {
	t.Helper()

	plaintext, err := os.ReadFile(source)
	require.NoError(t, err)

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	t.Setenv(sopsage.SopsAgeKeyEnv, identity.String())

	masterKey, err := sopsage.MasterKeyFromRecipient(identity.Recipient().String())
	require.NoError(t, err)

	dataKey := make([]byte, 32)
	_, err = rand.Read(dataKey)
	require.NoError(t, err)
	require.NoError(t, masterKey.Encrypt(dataKey))

	store := yaml.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plaintext)
	require.NoError(t, err)

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			EncryptedRegex: `^(password|username|token|value|key|raw)$`,
			KeyGroups:      []sops.KeyGroup{{masterKey}},
			Version:        version.Version,
		},
	}

	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	require.NoError(t, err)
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		mac,
		dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	require.NoError(t, err)

	encrypted, err := store.EmitEncryptedFile(tree)
	require.NoError(t, err)
	require.Contains(t, string(encrypted), "sops:")
	require.NotContains(t, string(encrypted), "1a2b3c4d5e6f7g8h9i0j")

	path := filepath.Join(t.TempDir(), "example-auth.yaml")
	require.NoError(t, os.WriteFile(path, encrypted, 0600))
	return path
}
