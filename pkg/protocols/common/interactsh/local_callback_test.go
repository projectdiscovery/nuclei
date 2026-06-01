package interactsh

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalCallbackReceivesHTTPInteraction(t *testing.T) {
	client := newLocalCallbackTestClient(t, "", "")

	generatedURL, err := client.NewURLWithData("{{interactsh-url}}")
	require.NoError(t, err)
	require.NotContains(t, generatedURL, "://")

	id := client.interactionIDFromURL(generatedURL)
	require.Len(t, id, 32)

	httpClient := &http.Client{Timeout: 2 * time.Second}
	request, err := http.NewRequest(http.MethodPost, "http://"+generatedURL+"?source=test", strings.NewReader("local-callback-body"))
	require.NoError(t, err)
	request.Header.Set("X-Nuclei-Test", "local-callback")

	response, err := httpClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	require.Equal(t, http.StatusOK, response.StatusCode)

	require.Eventually(t, func() bool {
		interactions, err := client.interactions.Get(id)
		if err != nil || len(interactions) != 1 {
			return false
		}
		interaction := interactions[0]
		return interaction.Protocol == "http" &&
			interaction.UniqueID == id &&
			interaction.RemoteAddress != "" &&
			strings.Contains(interaction.RawRequest, "POST /"+id+"?source=test HTTP/1.1") &&
			strings.Contains(interaction.RawRequest, "X-Nuclei-Test: local-callback") &&
			strings.Contains(interaction.RawRequest, "local-callback-body") &&
			strings.Contains(interaction.RawResponse, "HTTP/1.1 200 OK")
	}, time.Second, 10*time.Millisecond)
}

func TestLocalCallbackMakePlaceholdersUsesPathID(t *testing.T) {
	client := newLocalCallbackTestClient(t, "", "")

	generatedURL, err := client.NewURLWithData("{{interactsh-url}}")
	require.NoError(t, err)

	data := map[string]interface{}{}
	client.MakePlaceholders([]string{generatedURL}, data)

	require.Equal(t, generatedURL, data["interactsh-url"])
	require.Equal(t, client.interactionIDFromURL(generatedURL), data["interactsh-id"])
	require.Equal(t, client.localCallback.hostname(), data["interactsh-server"])
}

func TestParseCallbackURLSupportsSchemeLessHostPort(t *testing.T) {
	parsed, err := parseCallbackURL("10.10.14.251:8080/callback")
	require.NoError(t, err)
	require.Equal(t, "http", parsed.Scheme)
	require.Equal(t, "10.10.14.251:8080", parsed.Host)
	require.Equal(t, "/callback", parsed.Path)
}

func newLocalCallbackTestClient(t *testing.T, listenAddress, callbackURL string) *Client {
	t.Helper()
	if listenAddress == "" {
		listenAddress = "127.0.0.1:0"
	}
	client, err := New(&Options{
		CacheSize:           10,
		Eviction:            time.Second,
		CooldownPeriod:      0,
		PollDuration:        10 * time.Millisecond,
		LocalCallbackListen: listenAddress,
		LocalCallbackURL:    callbackURL,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
	})
	return client
}
