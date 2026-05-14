package goexec

import (
	"strings"
)

type credentialMode string

const (
	modePassword credentialMode = "password"
	modeNTHash   credentialMode = "nt_hash"
	modeKerberos credentialMode = "kerberos"
	modeAESKey   credentialMode = "aes_key"
	modeCCache   credentialMode = "ccache"
	modePFX      credentialMode = "pfx"
)

// Auth stores Windows authentication material for GoExec-backed helpers.
//
// The credential fields are intentionally unexported so JavaScript templates
// cannot serialize them back into findings, debug output, or stored responses.
type Auth struct {
	mode             credentialMode
	username         string
	password         string
	ntHash           string
	aesKey           string
	pfxPath          string
	pfxPassword      string
	ccache           string
	kerberos         bool
	domainController string
}

// AuthConstructors returns the JavaScript-facing Auth helper namespace.
func AuthConstructors() map[string]interface{} {
	return map[string]interface{}{
		"password": Password,
		"ntHash":   NTHash,
		"kerberos": Kerberos,
		"aesKey":   AESKey,
		"ccache":   CCache,
		"pfx":      PFX,
	}
}

// Password creates username/password authentication.
func Password(username, password string) *Auth {
	return &Auth{
		mode:     modePassword,
		username: username,
		password: password,
	}
}

// NTHash creates pass-the-hash authentication.
func NTHash(username, ntHash string, extra ...string) *Auth {
	if len(extra) > 0 && extra[0] != "" && !strings.Contains(ntHash, ":") {
		ntHash += ":" + extra[0]
	}
	return &Auth{
		mode:     modeNTHash,
		username: username,
		ntHash:   ntHash,
	}
}

// Kerberos creates Kerberos authentication with optional fields such as dc.
func Kerberos(username string, options ...interface{}) *Auth {
	auth := &Auth{
		mode:     modeKerberos,
		username: username,
		kerberos: true,
	}
	auth.applyAuthOptions(firstOption(options))
	return auth
}

// AESKey creates Kerberos AES-key authentication.
func AESKey(username, aesKey string, options ...interface{}) *Auth {
	auth := &Auth{
		mode:     modeAESKey,
		username: username,
		aesKey:   aesKey,
		kerberos: true,
	}
	auth.applyAuthOptions(firstOption(options))
	return auth
}

// CCache creates ccache authentication.
func CCache(path string) *Auth {
	return &Auth{
		mode:     modeCCache,
		ccache:   path,
		kerberos: true,
	}
}

// PFX creates PFX client certificate authentication.
func PFX(username, pfxPath, pfxPassword string) *Auth {
	return &Auth{
		mode:        modePFX,
		username:    username,
		pfxPath:     pfxPath,
		pfxPassword: pfxPassword,
		kerberos:    true,
	}
}

// MarshalJSON intentionally hides credential material from serialized output.
func (a *Auth) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

func firstOption(options []interface{}) interface{} {
	if len(options) == 0 {
		return nil
	}
	return options[0]
}

func (a *Auth) applyAuthOptions(raw interface{}) {
	values := mapFromAny(raw)
	if values == nil {
		return
	}
	if dc := stringValue(values, "dc", "domainController", "domain_controller"); dc != "" {
		a.domainController = dc
	}
	if kerberos, ok := boolValue(values, "kerberos"); ok {
		a.kerberos = kerberos
	}
	if password := stringValue(values, "password"); password != "" {
		a.password = password
	}
	if ntHash := stringValue(values, "ntHash", "nt_hash", "hash"); ntHash != "" {
		a.ntHash = ntHash
	}
	if ccache := stringValue(values, "ccache", "cCache"); ccache != "" {
		a.ccache = ccache
	}
}

func (a *Auth) validate() error {
	if a == nil {
		return ErrMissingAuth
	}
	selected := 0
	for _, value := range []string{a.password, a.ntHash, a.aesKey, a.pfxPath, a.ccache} {
		if value != "" {
			selected++
		}
	}
	switch {
	case selected == 0 && !a.kerberos:
		return ErrMissingAuth
	case selected > 1:
		// goexec/adauth always picks a single credential source. Allowing
		// more than one (even when kerberos is true) is almost certainly a
		// template mistake that would otherwise be silently truncated.
		return ErrMultipleCredentialModes
	case a.username == "" && a.mode != modeCCache:
		return ErrMissingUsername
	}
	return nil
}

func (a *Auth) secrets() []string {
	if a == nil {
		return nil
	}
	values := []string{
		a.password,
		a.ntHash,
		a.aesKey,
		a.pfxPassword,
		a.ccache,
	}
	if strings.ContainsAny(a.username, `\/@`) {
		values = append(values, a.username)
	}
	if strings.Contains(a.ntHash, ":") {
		values = append(values, strings.Split(a.ntHash, ":")...)
	}
	return compactStrings(values)
}

func compactStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
