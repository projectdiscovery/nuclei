package client

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSettings(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := SettingsService{Client: client}
	t.Run("SetSetting", func(t *testing.T) {
		err := svc.AddSetting(AddSettingRequest{
			Name:     "settings",
			Contents: "contents",
			Type:     "type",
		})
		require.NoError(t, err, "could not add setting")

	})
	t.Run("GetSettings", func(t *testing.T) {
		resp, err := svc.GetSettings()
		require.NoError(t, err, "could not get targets")
		require.Greater(t, len(resp), 0)
	})
	t.Run("UpdateSettingByName", func(t *testing.T) {
		err := svc.UpdateSetting(UpdateSettingRequest{
			Name:     "settings",
			Contents: "contents",
			Type:     "type",
		})
		require.NoError(t, err, "could not update setting")

	})
}

func TestGetSetting(t *testing.T) {
	setup := NewMockHttpServer(t)
	defer setup()
	client := New(WithBasicAuth("user", "pass"))
	svc := SettingsService{Client: client}
	resp, err := svc.GetSetting("name")
	require.NoError(t, err, "could not get setting")
	require.NotEmpty(t, resp)

}
