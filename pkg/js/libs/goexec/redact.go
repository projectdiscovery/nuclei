package goexec

import "strings"

const redacted = "[REDACTED]"

// Redactor removes credential material before data is returned to JavaScript.
type Redactor struct {
	secrets []string
}

func newRedactor(auth *Auth, extra ...string) *Redactor {
	secrets := []string{}
	if auth != nil {
		secrets = append(secrets, auth.secrets()...)
	}
	secrets = append(secrets, extra...)
	return &Redactor{secrets: compactStrings(secrets)}
}

// String redacts every known secret from value.
func (r *Redactor) String(value string) string {
	if r == nil || value == "" {
		return value
	}
	out := value
	for _, secret := range r.secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, redacted)
		out = strings.ReplaceAll(out, strings.ToLower(secret), redacted)
		out = strings.ReplaceAll(out, strings.ToUpper(secret), redacted)
	}
	return out
}

func (r *Redactor) Error(err error) string {
	if err == nil {
		return ""
	}
	return r.String(err.Error())
}
