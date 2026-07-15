package authx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebStorageSecret_GetStrategy(t *testing.T) {
	s := &Secret{
		Type:           string(WebStorageAuth),
		Domains:        []string{"app.example.com"},
		LocalStorage:   map[string]string{"jwt": "eyJ.payload.sig"},
		SessionStorage: map[string]string{"csrf": "tok"},
	}
	require.NoError(t, s.Validate())

	strategy := s.GetStrategy()
	require.NotNil(t, strategy)

	bsp, ok := strategy.(BrowserStorageProvider)
	require.True(t, ok, "web storage secret must yield a BrowserStorageProvider")
	local, session := bsp.WebStorage()
	require.Equal(t, "eyJ.payload.sig", local["jwt"])
	require.Equal(t, "tok", session["csrf"])
}

func TestWebStorageSecret_ValidateEmpty(t *testing.T) {
	s := &Secret{Type: string(WebStorageAuth), Domains: []string{"app.example.com"}}
	require.Error(t, s.Validate(), "web storage secret with no storage must be invalid")
}

func TestWebStorageSecret_SessionOnlyValid(t *testing.T) {
	s := &Secret{
		Type:           string(WebStorageAuth),
		Domains:        []string{"app.example.com"},
		SessionStorage: map[string]string{"csrf": "tok"},
	}
	require.NoError(t, s.Validate(), "session-storage alone should satisfy validation")
}
