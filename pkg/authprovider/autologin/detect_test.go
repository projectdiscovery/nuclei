package autologin

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestDetectLoginForm_Simple(t *testing.T) {
	body := `<html><body>
		<form action="/login" method="post">
			<input type="text" name="username">
			<input type="password" name="password">
			<button type="submit">Log in</button>
		</form>
	</body></html>`

	form, err := DetectLoginForm(body, mustURL(t, "https://app.example.com/auth"))
	require.NoError(t, err)
	require.Equal(t, "POST", form.Method)
	require.Equal(t, "https://app.example.com/login", form.Action)
	require.Equal(t, "username", form.UsernameField)
	require.Equal(t, "password", form.PasswordField)
}

func TestDetectLoginForm_EmailAndCSRF(t *testing.T) {
	body := `<html><body>
		<form action="https://id.example.com/sessions" method="POST">
			<input type="hidden" name="csrf_token" value="abc123">
			<input type="email" name="email" autocomplete="username">
			<input type="password" name="pass">
			<input type="submit" name="commit" value="Sign in">
		</form>
	</body></html>`

	form, err := DetectLoginForm(body, mustURL(t, "https://id.example.com/login"))
	require.NoError(t, err)
	require.Equal(t, "https://id.example.com/sessions", form.Action)
	require.Equal(t, "email", form.UsernameField)
	require.Equal(t, "pass", form.PasswordField)
	require.Equal(t, "abc123", form.Fields["csrf_token"], "CSRF hidden input must be carried")
	require.Equal(t, "Sign in", form.Fields["commit"], "named submit button should be carried")
	require.NotContains(t, form.Fields, "email", "username field must not be in extra fields")
	require.NotContains(t, form.Fields, "pass", "password field must not be in extra fields")
}

func TestDetectLoginForm_RelativeActionResolution(t *testing.T) {
	body := `<form action="../session" method="post">
		<input type="text" name="user">
		<input type="password" name="pwd">
	</form>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/app/login"))
	require.NoError(t, err)
	require.Equal(t, "https://example.com/session", form.Action)
}

func TestDetectLoginForm_MissingActionUsesPageURL(t *testing.T) {
	body := `<form method="post">
		<input type="text" name="user">
		<input type="password" name="pwd">
	</form>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/login?next=/home"))
	require.NoError(t, err)
	require.Equal(t, "https://example.com/login?next=/home", form.Action)
}

func TestDetectLoginForm_DefaultMethodIsPost(t *testing.T) {
	body := `<form action="/login">
		<input type="text" name="user">
		<input type="password" name="pwd">
	</form>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/login"))
	require.NoError(t, err)
	require.Equal(t, "POST", form.Method)
}

func TestDetectLoginForm_PicksLoginFormAmongMany(t *testing.T) {
	body := `<html><body>
		<form action="/search" method="get">
			<input type="text" name="q">
			<input type="submit" value="Search">
		</form>
		<form action="/newsletter" method="post">
			<input type="email" name="newsletter_email">
			<input type="submit" value="Subscribe">
		</form>
		<form action="/login" method="post">
			<input type="hidden" name="_token" value="xyz">
			<input type="text" name="login" autocomplete="username">
			<input type="password" name="password">
			<input type="submit" value="Sign in">
		</form>
	</body></html>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/"))
	require.NoError(t, err)
	require.Equal(t, "https://example.com/login", form.Action)
	require.Equal(t, "login", form.UsernameField)
	require.Equal(t, "password", form.PasswordField)
	require.Equal(t, "xyz", form.Fields["_token"])
}

func TestDetectLoginForm_UsernameHintBeatsOrder(t *testing.T) {
	// Two text inputs precede the password; the one with a username hint should
	// win even though it is not the closest to the password field.
	body := `<form action="/login" method="post">
		<input type="text" name="email" autocomplete="username">
		<input type="text" name="captcha">
		<input type="password" name="password">
	</form>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/login"))
	require.NoError(t, err)
	require.Equal(t, "email", form.UsernameField)
	require.NotContains(t, form.Fields, "captcha", "valueless non-username text input should not be injected")
}

func TestDetectLoginForm_NoPasswordField(t *testing.T) {
	body := `<form action="/search" method="get">
		<input type="text" name="q">
		<input type="submit" value="Search">
	</form>`

	_, err := DetectLoginForm(body, mustURL(t, "https://example.com/"))
	require.ErrorIs(t, err, ErrNoLoginForm)
}

func TestDetectLoginForm_SkipsMultiPasswordForms(t *testing.T) {
	// A registration / change-password form (two password fields) must not be
	// treated as a login form.
	body := `<form action="/register" method="post">
		<input type="text" name="username">
		<input type="password" name="password">
		<input type="password" name="password_confirm">
	</form>`

	_, err := DetectLoginForm(body, mustURL(t, "https://example.com/"))
	require.ErrorIs(t, err, ErrNoLoginForm)
}

func TestDetectLoginForm_PasswordOnlyForm(t *testing.T) {
	// A password-only form (no username) is still a valid login form.
	body := `<form action="/unlock" method="post">
		<input type="hidden" name="token" value="t">
		<input type="password" name="password">
	</form>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/unlock"))
	require.NoError(t, err)
	require.Equal(t, "", form.UsernameField)
	require.Equal(t, "password", form.PasswordField)
	require.Equal(t, "t", form.Fields["token"])
}

func TestDetectLoginForm_DefaultTypeIsText(t *testing.T) {
	// An input with no type attribute defaults to text and should be eligible as
	// the username field.
	body := `<form action="/login" method="post">
		<input name="user">
		<input type="password" name="pwd">
	</form>`

	form, err := DetectLoginForm(body, mustURL(t, "https://example.com/login"))
	require.NoError(t, err)
	require.Equal(t, "user", form.UsernameField)
}
