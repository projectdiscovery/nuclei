package har

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

const chromeHAR = "../testdata/chrome.har"

func parse(t *testing.T, input string) []*types.RequestResponse {
	t.Helper()
	file, err := os.Open(input)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var got []*types.RequestResponse
	require.NoError(t, New().Parse(file, func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, input))
	return got
}

func TestHARParse(t *testing.T) {
	got := parse(t, chromeHAR)

	urls := make([]string, 0, len(got))
	for _, rr := range got {
		urls = append(urls, rr.URL.String())
	}
	require.Equal(t, []string{
		"https://ginandjuice.shop/catalog?category=Juice",
		"https://ginandjuice.shop/login",
		"https://ginandjuice.shop/blocked.js",
	}, urls, "non-http entries such as data: URLs are skipped")
}

func TestHARParseHTTP2Request(t *testing.T) {
	rr := parse(t, chromeHAR)[0]

	require.Equal(t, "GET", rr.Request.Method)
	cookie, _ := rr.Request.Headers.Get("cookie")
	require.Equal(t, "session=abc123", cookie)
	for _, name := range rr.Request.Headers.GetKeys() {
		require.False(t, strings.HasPrefix(name, ":"), "pseudo-header %s is not a real header", name)
	}

	req, err := rr.BuildRequest()
	require.NoError(t, err)
	require.Equal(t, "ginandjuice.shop", req.Host)
}

func TestHARParseBodyAndResponse(t *testing.T) {
	got := parse(t, chromeHAR)

	login := got[1]
	require.Equal(t, "POST", login.Request.Method)
	require.Equal(t, "username=carlos&password=hunter2", login.Request.Body)
	require.NotNil(t, login.Response)
	require.Contains(t, login.Response.Raw, "302 Found")
	require.Contains(t, login.Response.Raw, "Location: /my-account")

	require.NotNil(t, got[0].Response)
	require.Contains(t, got[0].Response.Raw, "<h1>Juice</h1>", "base64 content is decoded")

	require.Nil(t, got[2].Response, "a request that never got an answer has no response")
}
