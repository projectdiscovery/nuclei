package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestActionNavigate(t *testing.T) {
	_ = protocolstate.Init(&types.Options{})

	browser, err := New(&types.Options{ShowBrowser: false})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")
	defer instance.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>
			<h1>Nuclei Test</h1>
		</body>
	</html>`)
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	require.Nil(t, err, "could not parse URL")

	actions := []*Action{{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}}, {ActionType: "waitload"}}
	_, page, err := instance.Run(parsed, actions, 20*time.Second)
	require.Nil(t, err, "could not run page actions")
	defer page.Close()

	require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
}

func TestActionScript(t *testing.T) {
	_ = protocolstate.Init(&types.Options{})

	browser, err := New(&types.Options{ShowBrowser: false})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")

	t.Run("run-and-results", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `
			<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
			<script>window.test = 'some-data';</script>
		</html>`)
		}))
		defer ts.Close()

		parsed, err := url.Parse(ts.URL)
		require.Nil(t, err, "could not parse URL")

		actions := []*Action{
			{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
			{ActionType: "waitload"},
			{ActionType: "script", Name: "test", Data: map[string]string{"code": "window.test"}},
		}
		out, page, err := instance.Run(parsed, actions, 20*time.Second)
		require.Nil(t, err, "could not run page actions")
		defer page.Close()

		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		require.Equal(t, "some-data", out["test"], "could not run js and get results correctly")
	})

	t.Run("hook", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `
			<html>
			<head>
				<title>Nuclei Test Page</title>
			</head>
			<body>Nuclei Test Page</body>
		</html>`)
		}))
		defer ts.Close()

		parsed, err := url.Parse(ts.URL)
		require.Nil(t, err, "could not parse URL")

		actions := []*Action{
			{ActionType: "script", Data: map[string]string{"code": "window.test = 'some-data';", "hook": "true"}},
			{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
			{ActionType: "waitload"},
			{ActionType: "script", Name: "test", Data: map[string]string{"code": "window.test"}},
		}
		out, page, err := instance.Run(parsed, actions, 20*time.Second)
		require.Nil(t, err, "could not run page actions")
		defer page.Close()

		require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
		require.Equal(t, "some-data", out["test"], "could not run js and get results correctly with js hook")
	})
}

func TestActionClick(t *testing.T) {
	_ = protocolstate.Init(&types.Options{})

	browser, err := New(&types.Options{ShowBrowser: false})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>Nuclei Test Page</body>
		<button onclick='this.setAttribute("a", "ok")'>click me</button>
	</html>`)
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	require.Nil(t, err, "could not parse URL")

	actions := []*Action{
		{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: "waitload"},
		{ActionType: "click", Data: map[string]string{"selector": "button"}}, // Use css selector for clicking
	}
	_, page, err := instance.Run(parsed, actions, 20*time.Second)
	require.Nil(t, err, "could not run page actions")
	defer page.Close()

	require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
	el := page.Page().MustElement("button")
	val := el.MustAttribute("a")
	require.Equal(t, "ok", *val, "could not click button")
}

func TestActionRightClick(t *testing.T) {
	_ = protocolstate.Init(&types.Options{})

	browser, err := New(&types.Options{ShowBrowser: false})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>Nuclei Test Page</body>
		<button id="test" onrightclick=''>click me</button>
		<script>
		elm = document.getElementById("test");
		elm.onmousedown = function(event) {
			if (event.which == 3) {
				elm.setAttribute("a", "ok")
			}
		}
		</script>
	</html>`)
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	require.Nil(t, err, "could not parse URL")

	actions := []*Action{
		{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: "waitload"},
		{ActionType: "rightclick", Data: map[string]string{"selector": "button"}}, // Use css selector for clicking
	}
	_, page, err := instance.Run(parsed, actions, 20*time.Second)
	require.Nil(t, err, "could not run page actions")
	defer page.Close()

	require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
	el := page.Page().MustElement("button")
	val := el.MustAttribute("a")
	require.Equal(t, "ok", *val, "could not click button")
}

func TestActionTextInput(t *testing.T) {
	_ = protocolstate.Init(&types.Options{})

	browser, err := New(&types.Options{ShowBrowser: false})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		<html>
		<head>
			<title>Nuclei Test Page</title>
		</head>
		<body>Nuclei Test Page</body>
		<input type="text" onchange="this.setAttribute('event', 'input-change')">
	</html>`)
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	require.Nil(t, err, "could not parse URL")

	actions := []*Action{
		{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: "waitload"},
		{ActionType: "text", Data: map[string]string{"selector": "input", "value": "test"}},
	}
	_, page, err := instance.Run(parsed, actions, 20*time.Second)
	require.Nil(t, err, "could not run page actions")
	defer page.Close()

	require.Equal(t, "Nuclei Test Page", page.Page().MustInfo().Title, "could not navigate correctly")
	el := page.Page().MustElement("input")
	val := el.MustAttribute("event")
	require.Equal(t, "input-change", *val, "could not get input change")
	require.Equal(t, "test", el.MustText(), "could not get input change value")
}

func TestActionHeadersChange(t *testing.T) {
	_ = protocolstate.Init(&types.Options{})

	browser, err := New(&types.Options{ShowBrowser: false})
	require.Nil(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.Nil(t, err, "could not create browser instance")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Test") == "Hello" {
			fmt.Fprintln(w, `found`)
		}
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	require.Nil(t, err, "could not parse URL")

	actions := []*Action{
		{ActionType: "setheader", Data: map[string]string{"part": "request", "key": "Test", "value": "Hello"}},
		{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: "waitload"},
	}
	_, page, err := instance.Run(parsed, actions, 20*time.Second)
	require.Nil(t, err, "could not run page actions")
	defer page.Close()

	require.Equal(t, "found", strings.ToLower(strings.TrimSpace(page.Page().MustElement("html").MustText())), "could not set header correctly")
}
