package authx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretsUnmarshal(t *testing.T) {
	loc := "testData/example-auth.yaml"
	data, err := GetAuthDataFromFile(loc)
	require.Nil(t, err, "could not read secrets file")
	require.NotNil(t, data, "could not read secrets file")
	for _, s := range data.Secrets {
		require.Nil(t, s.Validate(), "could not validate secret")
	}
	for _, d := range data.Dynamic {
		require.Nil(t, d.Validate(), "could not validate dynamic")
	}
}

func Test_Cookie_Parse_keeps_equals_in_value(t *testing.T) {
	// Given
	cookie := &Cookie{Raw: "Set-Cookie: session=YWJjZA==; Path=/; HttpOnly"}

	// When
	err := cookie.Parse()

	// Then
	require.NoError(t, err)
	require.Equal(t, "session", cookie.Key)
	require.Equal(t, "YWJjZA==", cookie.Value)
}
