package authx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretsUnmarshal(t *testing.T) {
	loc := "testData/secrets.yaml"
	data, err := GetAuthDataFromFile(loc)
	require.Nil(t, err, "could not read secrets file")
	require.NotNil(t, data, "could not read secrets file")
	for _, s := range data.Secrets {
		require.Nil(t, s.Validate(), "could not validate secret")
	}
}
