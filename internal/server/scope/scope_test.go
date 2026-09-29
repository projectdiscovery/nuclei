package scope

import (
	"net/url"
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestManagerValidate(t *testing.T) {
	t.Run("url", func(t *testing.T) {
		manager, err := NewManager([]string{`example`}, []string{`logout\.php`})
		require.NoError(t, err, "could not create scope manager")

		parsed, _ := urlutil.Parse("https://test.com/index.php/example")
		validated, err := manager.Validate(parsed.URL)
		require.NoError(t, err, "could not validate url")
		require.True(t, validated, "could not get correct in-scope validation")

		parsed, _ = urlutil.Parse("https://test.com/logout.php")
		validated, err = manager.Validate(parsed.URL)
		require.NoError(t, err, "could not validate url")
		require.False(t, validated, "could not get correct out-scope validation")
	})

}

func TestManagerIsExplicitlyOutOfScope(t *testing.T) {
	manager, err := NewManager(
		[]string{`^https://app\.example\.com/api/`},
		[]string{`^https://telemetry\.example\.com/`},
	)
	require.NoError(t, err)

	excluded, err := url.Parse("https://telemetry.example.com/")
	require.NoError(t, err)
	require.True(t, manager.IsExplicitlyOutOfScope(excluded))

	// Not matching an in-scope rule is not the same as being excluded.
	unlisted, err := url.Parse("https://app.example.com/")
	require.NoError(t, err)
	require.False(t, manager.IsExplicitlyOutOfScope(unlisted))
}
