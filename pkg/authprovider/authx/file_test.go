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

func TestDynamicUnmarshal(t *testing.T) {
	loc := "testData/dynamic.yaml"
	data, err := GetAuthDataFromFile(loc)
	require.Nil(t, err, "could not read dynamic file")
	require.NotNil(t, data, "could not read dynamic file")
	for _, d := range data.Dynamic {
		require.Nil(t, d.Validate(), "could not validate dynamic")
	}
}
