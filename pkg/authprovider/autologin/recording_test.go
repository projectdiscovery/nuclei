package autologin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// chromeRecording is a representative Chrome DevTools Recorder export of a
// username-first login, including the noise (setViewport, paired keyUp) and the
// multiple selector strategies Chrome emits per step.
const chromeRecording = `{
  "title": "login",
  "steps": [
    {"type": "setViewport", "width": 1280, "height": 720},
    {"type": "navigate", "url": "https://app.example.com/login"},
    {"type": "change", "value": "dave@example.com", "selectors": [["#email"], ["aria/Email"], ["xpath///*[@id=\"email\"]"]]},
    {"type": "click", "selectors": [["#next"], ["aria/Next"]]},
    {"type": "waitForElement", "selectors": [["#password"]]},
    {"type": "change", "value": "p@ss", "selectors": [["#password"]]},
    {"type": "keyDown", "key": "Enter"},
    {"type": "keyUp", "key": "Enter"},
    {"type": "click", "selectors": [["#submit"]]}
  ]
}`

func TestStepsFromRecording_MapsAndParameterizes(t *testing.T) {
	steps, err := StepsFromRecording([]byte(chromeRecording), "dave@example.com", "p@ss")
	require.NoError(t, err)

	require.Equal(t, []LoginStep{
		{Action: "navigate", Value: "https://app.example.com/login"},
		{Action: "fill", Selector: "#email", Value: "{{username}}"},
		{Action: "click", Selector: "#next"},
		{Action: "waitvisible", Selector: "#password"},
		{Action: "fill", Selector: "#password", Value: "{{password}}"},
		{Action: "press", Value: "enter"},
		{Action: "click", Selector: "#submit"},
	}, steps, "recording should map to placeholder-parameterized steps (setViewport/keyUp dropped)")
}

func TestStepsFromRecording_PasswordSelectorMaskedWithoutCredMatch(t *testing.T) {
	// Even if the recorded literal doesn't match configured creds, a value typed
	// into a password-looking field must never survive in the steps.
	rec := `{"steps": [
		{"type": "change", "value": "literal-secret", "selectors": [["input[type=password]"]]}
	]}`
	steps, err := StepsFromRecording([]byte(rec), "", "")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	require.Equal(t, "{{password}}", steps[0].Value, "value typed into a password field must be masked")
}

func TestStepsFromRecording_SelectorPriority(t *testing.T) {
	// CSS preferred over aria/xpath; xpath/ prefix becomes an engine xpath= form;
	// aria-only falls back to an aria-label CSS approximation; pierce/ is ignored.
	rec := `{"steps": [
		{"type": "click", "selectors": [["aria/Save"], ["xpath///button[1]"], ["#real"]]},
		{"type": "click", "selectors": [["pierce/#shadow"], ["xpath///div[2]"]]},
		{"type": "click", "selectors": [["aria/Submit"]]}
	]}`
	steps, err := StepsFromRecording([]byte(rec), "", "")
	require.NoError(t, err)
	require.Equal(t, "#real", steps[0].Selector, "CSS should win over aria/xpath")
	require.Equal(t, "xpath=//div[2]", steps[1].Selector, "xpath used when no CSS, pierce ignored")
	require.Equal(t, `[aria-label="Submit"]`, steps[2].Selector, "aria falls back to aria-label CSS")
}

func TestStepsFromRecording_Errors(t *testing.T) {
	_, err := StepsFromRecording([]byte(`not json`), "", "")
	require.Error(t, err)

	_, err = StepsFromRecording([]byte(`{"steps": []}`), "", "")
	require.Error(t, err, "empty recording must error")

	_, err = StepsFromRecording([]byte(`{"steps": [{"type":"setViewport"}]}`), "", "")
	require.Error(t, err, "recording with no replayable steps must error")
}

func TestFirstNavigateURL(t *testing.T) {
	steps := []LoginStep{
		{Action: "fill", Selector: "#x"},
		{Action: "navigate", Value: "https://app.example.com/login"},
		{Action: "navigate", Value: "https://second"},
	}
	require.Equal(t, "https://app.example.com/login", FirstNavigateURL(steps))
	require.Equal(t, "", FirstNavigateURL([]LoginStep{{Action: "click"}}))
}

// TestLoginHeadless_FromRecording proves an end-to-end recorded login: a Chrome
// recording is compiled to steps (one of them an XPath selector) and replayed by
// the headless engine against a real browser to acquire the session.
func TestLoginHeadless_FromRecording(t *testing.T) {
	requireChrome(t)

	app := newJSLoginApp()
	srv := httptest.NewServer(func() http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, twoStepLoginPage)
				return
			}
			_ = r.ParseForm()
			if r.PostFormValue("email") != "dave@example.com" || r.PostFormValue("password") != "p@ss" {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, twoStepLoginPage)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-dave", Path: "/"})
			app.mu.Lock()
			app.sessions["sess-dave"] = true
			app.mu.Unlock()
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		})
		mux.HandleFunc("/dashboard", app.handleDashboard)
		return mux
	}())
	defer srv.Close()

	// The "next" click uses an XPath selector to exercise the engine's XPath path.
	recording := fmt.Sprintf(`{"steps": [
		{"type": "navigate", "url": %q},
		{"type": "change", "value": "dave@example.com", "selectors": [["#email"]]},
		{"type": "click", "selectors": [["xpath///*[@id=\"next\"]"]]},
		{"type": "waitForElement", "selectors": [["#password"]]},
		{"type": "change", "value": "p@ss", "selectors": [["#password"]]},
		{"type": "click", "selectors": [["#submit"]]}
	]}`, srv.URL+"/login")

	steps, err := StepsFromRecording([]byte(recording), "dave@example.com", "p@ss")
	require.NoError(t, err)
	require.Equal(t, "xpath=//*[@id=\"next\"]", steps[2].Selector, "recorded xpath selector should be preserved")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session, err := LoginHeadless(ctx, Config{
		LoginURL:   FirstNavigateURL(steps),
		Username:   "dave@example.com",
		Password:   "p@ss",
		SettleTime: 1 * time.Second,
		Steps:      steps,
	})
	require.NoError(t, err)

	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Contains(t, names, "session", "recorded login should capture the session cookie")
}
