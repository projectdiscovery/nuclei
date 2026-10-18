// Package orca implements OrcaRouter as a first-class provider for nuclei's
// semantic-matching (llm matcher/extractor) layer.
//
// It exists because nuclei's shared provider table lives in the external
// projectdiscovery/utils module and therefore cannot carry a new preset. The
// package owns the parts nuclei needs and utils cannot express: the OrcaRouter
// endpoint presets, the two credential sources (a pasted API key and an
// OAuth 2.0 + PKCE connect flow), the durable credential store, and live model
// discovery with capability filtering.
//
// Authentication and inference deliberately use different public origins:
// https://www.orcarouter.ai for /auth and /api/v1/auth/keys, and
// https://api.orcarouter.ai/v1 for inference and model discovery. Neither is
// derived from the other.
package orca

import (
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
)

// Default origins. Authentication is not served from the inference origin:
// https://api.orcarouter.ai/v1/auth/keys is a 404.
const (
	DefaultAuthBaseURL = "https://www.orcarouter.ai"
	DefaultAPIBaseURL  = "https://api.orcarouter.ai/v1"

	// AuthPath is the browser consent screen.
	AuthPath = "/auth"
	// ExchangePath is the code-for-key endpoint, on the auth origin.
	ExchangePath = "/api/v1/auth/keys"
	// ModelsPath is model discovery, on the inference origin.
	ModelsPath = "/models"
	// ChatCompletionsPath is the inference endpoint.
	ChatCompletionsPath = "/chat/completions"

	// ConsoleURL is where a user revokes keys issued to this application.
	ConsoleURL = "https://www.orcarouter.ai/console/authorized-apps"

	// AppName labels this client on the consent screen.
	AppName = "nuclei"
)

// Environment variables. The explicit per-origin overrides take precedence over
// the shared self-hosted fallback, which takes precedence over the public
// defaults.
const (
	EnvAuthBaseURL = "ORCA_AUTH_BASE_URL"
	EnvAPIBaseURL  = "ORCA_API_BASE_URL"
	EnvSharedBase  = "ORCA_BASE_URL"
)

// Endpoints holds the resolved origins for one configuration.
type Endpoints struct {
	// Auth is the origin serving /auth and /api/v1/auth/keys, without a
	// trailing slash.
	Auth string
	// API is the OpenAI-compatible inference base, without a trailing slash.
	API string
}

// resolveEndpoints applies the override precedence documented above. authOverride
// and apiOverride are the explicit per-origin values (already read from flags or
// config by the caller); sharedOverride is the self-hosted single-origin
// fallback.
func resolveEndpoints(authOverride, apiOverride, sharedOverride string) Endpoints {
	auth := firstNonEmpty(authOverride, sharedOverride, DefaultAuthBaseURL)
	api := firstNonEmpty(apiOverride, sharedOverride, DefaultAPIBaseURL)

	return Endpoints{
		Auth: strings.TrimSuffix(strings.TrimSpace(auth), "/"),
		API:  strings.TrimSuffix(strings.TrimSpace(api), "/"),
	}
}

// EndpointsFromEnv resolves the origins from the documented environment
// variables only.
func EndpointsFromEnv() Endpoints {
	return resolveEndpoints(
		os.Getenv(EnvAuthBaseURL),
		os.Getenv(EnvAPIBaseURL),
		os.Getenv(EnvSharedBase),
	)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}

	return ""
}

// ValidateEndpoints rejects an origin a credential could be sent to in clear
// text. A remote origin must be HTTPS; plain HTTP is permitted only for a
// loopback host, which is what a local self-hosted gateway uses during
// development.
func ValidateEndpoints(endpoints Endpoints) error {
	if err := validateOrigin("auth", endpoints.Auth); err != nil {
		return err
	}

	return validateOrigin("api", endpoints.API)
}

func validateOrigin(label, raw string) error {
	if raw == "" {
		return errkit.Newf("orcarouter %s base url is empty", label)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return errkit.Wrapf(err, "orcarouter %s base url is not a valid url", label)
	}
	if parsed.Host == "" {
		return errkit.Newf("orcarouter %s base url %q has no host", label, raw)
	}
	if parsed.User != nil {
		return errkit.Newf("orcarouter %s base url must not carry userinfo", label)
	}

	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return errkit.Newf(
				"orcarouter %s base url %q uses plain http for a non-loopback host; use https",
				label,
				raw,
			)
		}

		return nil
	default:
		return errkit.Newf(
			"orcarouter %s base url %q must use https (http is allowed only for loopback)",
			label,
			raw,
		)
	}
}

// isLoopbackHost reports whether host names the local machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	address := net.ParseIP(host)
	if address == nil {
		return false
	}

	return address.IsLoopback()
}

// authURL joins a path onto the auth origin.
func (e Endpoints) authURL(path string) string {
	return e.Auth + path
}

// apiURL joins a path onto the inference origin.
func (e Endpoints) apiURL(path string) string {
	return e.API + path
}
