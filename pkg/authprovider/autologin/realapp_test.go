package autologin

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Real-application harness. These tests are skipped unless NUCLEI_REALAPP_LOGIN_URL
// is set, so normal CI is unaffected. They drive the headless engine against a
// live app to flush out engine bugs that synthetic httptest servers miss
// (heavy SPA bootstrap, XHR logins, hash routes, token-in-web-storage, etc.).
//
// Example (OWASP Juice Shop):
//
//	docker run -d -p 3000:3000 bkimminich/juice-shop
//	NUCLEI_REALAPP_LOGIN_URL='http://localhost:3000/#/login' \
//	NUCLEI_REALAPP_USERNAME='admin@juice-sh.op' \
//	NUCLEI_REALAPP_PASSWORD='admin123' \
//	NUCLEI_REALAPP_TOKEN_REGEX='(eyJ[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)' \
//	NUCLEI_REALAPP_EXPECT_STORAGE_KEY='token' \
//	go test ./pkg/authprovider/autologin/ -run TestRealApp_HeadlessLogin -v
func realAppConfig(t *testing.T) (Config, bool) {
	t.Helper()
	loginURL := os.Getenv("NUCLEI_REALAPP_LOGIN_URL")
	if loginURL == "" {
		t.Skip("set NUCLEI_REALAPP_LOGIN_URL to run the real-app login harness")
		return Config{}, false
	}
	cfg := Config{
		LoginURL:      loginURL,
		Username:      os.Getenv("NUCLEI_REALAPP_USERNAME"),
		Password:      os.Getenv("NUCLEI_REALAPP_PASSWORD"),
		UsernameField: os.Getenv("NUCLEI_REALAPP_USERNAME_FIELD"),
		PasswordField: os.Getenv("NUCLEI_REALAPP_PASSWORD_FIELD"),
		TokenRegex:    os.Getenv("NUCLEI_REALAPP_TOKEN_REGEX"),
		Proxy:         os.Getenv("NUCLEI_REALAPP_PROXY"),
		SettleTime:    8 * time.Second,
		Timeout:       90 * time.Second,
	}
	if steps := os.Getenv("NUCLEI_REALAPP_STEPS"); steps != "" {
		require.NoError(t, json.Unmarshal([]byte(steps), &cfg.Steps), "NUCLEI_REALAPP_STEPS must be a JSON array of LoginStep")
	}
	return cfg, true
}

func logSession(t *testing.T, s *Session) {
	t.Helper()
	t.Logf("final url: %s", s.FinalURL)
	t.Logf("cookies (%d):", len(s.Cookies))
	for _, c := range s.Cookies {
		v := c.Value
		if len(v) > 24 {
			v = v[:24] + "...(truncated)"
		}
		t.Logf("  %s = %s", c.Name, v)
	}
	if s.Token != "" {
		tok := s.Token
		if len(tok) > 32 {
			tok = tok[:32] + "...(truncated)"
		}
		t.Logf("token: %s", tok)
	}
	t.Logf("localStorage keys: %d, sessionStorage keys: %d", len(s.LocalStorage), len(s.SessionStorage))
	for k := range s.LocalStorage {
		t.Logf("  local[%s]", k)
	}
	for k := range s.SessionStorage {
		t.Logf("  session[%s]", k)
	}
}

func TestRealApp_HeadlessLogin(t *testing.T) {
	requireChrome(t)
	cfg, ok := realAppConfig(t)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	session, err := LoginHeadless(ctx, cfg)
	require.NoError(t, err, "headless login against real app failed")
	logSession(t, session)

	require.True(t, len(session.Cookies) > 0 || session.Token != "" || len(session.LocalStorage) > 0,
		"expected to capture a session (cookie, token or web storage)")

	if key := os.Getenv("NUCLEI_REALAPP_EXPECT_STORAGE_KEY"); key != "" {
		_, inLocal := session.LocalStorage[key]
		_, inSession := session.SessionStorage[key]
		require.True(t, inLocal || inSession, "expected web storage key %q to be captured", key)
	}
	if name := os.Getenv("NUCLEI_REALAPP_EXPECT_COOKIE"); name != "" {
		found := false
		for _, c := range session.Cookies {
			if c.Name == name {
				found = true
				break
			}
		}
		require.True(t, found, "expected cookie %q to be captured", name)
	}
}

// TestRealApp_RecordingReplay drives a recorder-JSON login flow (compiled to
// steps, with credential parameterization) against the live app, exercising the
// full record->replay path end to end. Set NUCLEI_REALAPP_RECORDING to a Chrome
// DevTools Recorder export to run it.
func TestRealApp_RecordingReplay(t *testing.T) {
	requireChrome(t)
	cfg, ok := realAppConfig(t)
	if !ok {
		return
	}
	recording := os.Getenv("NUCLEI_REALAPP_RECORDING")
	if recording == "" {
		t.Skip("set NUCLEI_REALAPP_RECORDING to a recorder json to run the replay harness")
	}

	steps, err := StepsFromRecordingFile(recording, cfg.Username, cfg.Password)
	require.NoError(t, err, "failed to compile recording")
	t.Logf("compiled %d steps from recording", len(steps))
	for _, s := range steps {
		t.Logf("  %s selector=%q value=%q", s.Action, s.Selector, s.Value)
	}
	cfg.Steps = steps
	if cfg.LoginURL == "" {
		cfg.LoginURL = FirstNavigateURL(steps)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	session, err := LoginHeadless(ctx, cfg)
	require.NoError(t, err, "recorded login replay against real app failed")
	logSession(t, session)
	require.True(t, len(session.Cookies) > 0 || session.Token != "" || len(session.LocalStorage) > 0,
		"expected recorded login to capture a session")
}
