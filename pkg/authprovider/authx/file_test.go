package authx

import (
	"testing"

	"github.com/getsops/sops/v3/pgp"
	"github.com/stretchr/testify/require"
)

func TestSecretsUnmarshal(t *testing.T) {
	data, err := GetAuthDataFromFile("testData/example-auth.yaml")
	require.Nil(t, err, "could not read secrets file")
	require.NotNil(t, data, "could not read secrets file")

	for _, s := range data.Secrets {
		require.Nil(t, s.Validate(), "could not validate secret")
	}

	for _, d := range data.Dynamic {
		require.Nil(t, d.Validate(), "could not validate dynamic")
	}

	t.Run("encrypted", func(t *testing.T) {
		loc := "testData/example-auth.yaml"
		gnupgHome, err := pgp.NewGnuPGHome()
		require.NoError(t, err)

		defer func() {
			err := gnupgHome.Cleanup()
			require.NoError(t, err)
		}()

		err = gnupgHome.ImportFile("testData/private.asc")
		require.NoError(t, err)

		err = gnupgHome.ImportFile("testData/public.asc")
		require.NoError(t, err)

		decryptedData, err := GetAuthDataFromFile(loc)
		require.Nil(t, err, "could not read secrets file")
		require.NotNil(t, decryptedData, "could not read secrets file")
		require.Equal(t, data, decryptedData, "decrypted data should match original data")

		for _, s := range decryptedData.Secrets {
			require.Nil(t, s.Validate(), "could not validate secret")
		}

		for _, d := range decryptedData.Dynamic {
			require.Nil(t, d.Validate(), "could not validate dynamic")
		}
	})
}
