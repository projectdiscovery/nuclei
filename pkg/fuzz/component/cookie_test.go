package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestCookieComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{
		Name:  "session",
		Value: "test-session",
	}
	req.AddCookie(cookie)

	cookieComponent := NewCookie() // Assuming you have a function like this for creating a new cookie component
	_, err = cookieComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var cookieNames []string
	var cookieValues []string
	_ = cookieComponent.Iterate(func(key string, value interface{}) error {
		cookieNames = append(cookieNames, key)
		switch v := value.(type) {
		case string:
			cookieValues = append(cookieValues, v)
		case []string:
			cookieValues = append(cookieValues, v...)
		}
		return nil
	})

	require.Equal(t, []string{"session"}, cookieNames, "unexpected cookie names")
	require.Equal(t, []string{"test-session"}, cookieValues, "unexpected cookie values")

	err = cookieComponent.SetValue("session", "new-session")
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := cookieComponent.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	// Assuming the Rebuild function will reconstruct the entire request and also set the modified cookies
	newCookie, _ := rebuilt.Cookie("session")
	require.Equal(t, "new-session", newCookie.Value, "unexpected cookie value")
}
