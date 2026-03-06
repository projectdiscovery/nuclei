package authx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/errkit"
	"github.com/projectdiscovery/utils/generic"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"gopkg.in/yaml.v3"
)

type AuthType string

const (
	BasicAuth       AuthType = "BasicAuth"
	BearerTokenAuth AuthType = "BearerToken"
	HeadersAuth     AuthType = "Header"
	CookiesAuth     AuthType = "Cookie"
	QueryAuth       AuthType = "Query"
)

// SupportedAuthTypes returns the supported auth types
func SupportedAuthTypes() []string {
	return []string{
		string(BasicAuth),
		string(BearerTokenAuth),
		string(HeadersAuth),
		string(CookiesAuth),
		string(QueryAuth),
	}
}

// Authx is a struct for secrets or credentials file
type Authx struct {
	ID      string       `json:"id" yaml:"id"`
	Info    AuthFileInfo `json:"info" yaml:"info"`
	Secrets []Secret     `json:"static" yaml:"static"`
	Dynamic []Dynamic    `json:"dynamic" yaml:"dynamic"`
}

type AuthFileInfo struct {
	Name        string `json:"name" yaml:"name"`
	Author      string `json:"author" yaml:"author"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
}

// Secret is a struct for secret or credential
type Secret struct {
	Type            string   `json:"type" yaml:"type"`
	Domains         []string `json:"domains" yaml:"domains"`
	DomainsRegex    []string `json:"domains-regex" yaml:"domains-regex"`
	Headers         []KV     `json:"headers" yaml:"headers"` // Headers preserve exact casing (useful for case-sensitive APIs)
	Cookies         []Cookie `json:"cookies" yaml:"cookies"`
	Params          []KV     `json:"params" yaml:"params"`
	Username        string   `json:"username" yaml:"username"` // can be either email or username
	Password        string   `json:"password" yaml:"password"`
	Token           string   `json:"token" yaml:"token"` // Bearer Auth token
	skipCookieParse bool     `json:"-" yaml:"-"`         // temporary flag to skip cookie parsing (used in dynamic secrets)
}

// GetStrategy returns the auth strategy for the secret
func (s *Secret) GetStrategy() AuthStrategy {
	switch {
	case strings.EqualFold(s.Type, string(BasicAuth)):
		return NewBasicAuthStrategy(s)
	case strings.EqualFold(s.Type, string(BearerTokenAuth)):
		return NewBearerTokenAuthStrategy(s)
	case strings.EqualFold(s.Type, string(HeadersAuth)):
		return NewHeadersAuthStrategy(s)
	case strings.EqualFold(s.Type, string(CookiesAuth)):
		return NewCookiesAuthStrategy(s)
	case strings.EqualFold(s.Type, string(QueryAuth)):
		return NewQueryAuthStrategy(s)
	}
	return nil
}

func (s *Secret) Validate() error {
	if !stringsutil.EqualFoldAny(s.Type, SupportedAuthTypes()...) {
		return fmt.Errorf("invalid type: %s", s.Type)
	}
	if len(s.Domains) == 0 && len(s.DomainsRegex) == 0 {
		return fmt.Errorf("domains or domains-regex cannot be empty")
	}
	if len(s.DomainsRegex) > 0 {
		for _, domain := range s.DomainsRegex {
			if err := validateDomainRegex(domain); err != nil {
				return err
			}
		}
	}

	switch {
	case strings.EqualFold(s.Type, string(BasicAuth)):
		if s.Username == "" {
			return fmt.Errorf("username cannot be empty in basic auth")
		}
		if s.Password == "" {
			return fmt.Errorf("password cannot be empty in basic auth")
		}
	case strings.EqualFold(s.Type, string(BearerTokenAuth)):
		if s.Token == "" {
			return fmt.Errorf("token cannot be empty in bearer token auth")
		}
	case strings.EqualFold(s.Type, string(HeadersAuth)):
		if len(s.Headers) == 0 {
			return fmt.Errorf("headers cannot be empty in headers auth")
		}
		for _, header := range s.Headers {
			if err := header.Validate(); err != nil {
				return fmt.Errorf("invalid header in headersAuth: %s", err)
			}
		}
	case strings.EqualFold(s.Type, string(CookiesAuth)):
		if len(s.Cookies) == 0 {
			return fmt.Errorf("cookies cannot be empty in cookies auth")
		}
		for _, cookie := range s.Cookies {
			if cookie.Raw != "" && !s.skipCookieParse {
				if err := cookie.Parse(); err != nil {
					return fmt.Errorf("invalid raw cookie in cookiesAuth: %s", err)
				}
			}
			if err := cookie.Validate(); err != nil {
				return fmt.Errorf("invalid cookie in cookiesAuth: %s", err)
			}
		}
	case strings.EqualFold(s.Type, string(QueryAuth)):
		if len(s.Params) == 0 {
			return fmt.Errorf("query cannot be empty in query auth")
		}
		for _, query := range s.Params {
			if err := query.Validate(); err != nil {
				return fmt.Errorf("invalid query in queryAuth: %s", err)
			}
		}
	default:
		return fmt.Errorf("invalid type: %s", s.Type)
	}
	return nil
}

type KV struct {
	Key   string `json:"key" yaml:"key"` // Header key (preserves exact casing)
	Value string `json:"value" yaml:"value"`
}

func (k *KV) Validate() error {
	if k.Key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	if k.Value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	return nil
}

type Cookie struct {
	Key   string `json:"key" yaml:"key"`
	Value string `json:"value" yaml:"value"`
	Raw   string `json:"raw" yaml:"raw"`
}

func (c *Cookie) Validate() error {
	if c.Raw != "" {
		return nil
	}
	if c.Key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	if c.Value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	return nil
}

// Parse parses the cookie
// in raw the cookie is in format of
// Set-Cookie: <cookie-name>=<cookie-value>; Expires=<date>; Path=<path>; Domain=<domain_name>; Secure; HttpOnly
func (c *Cookie) Parse() error {
	if c.Raw == "" {
		return fmt.Errorf("raw cookie cannot be empty")
	}
	tmp := strings.TrimPrefix(c.Raw, "Set-Cookie: ")
	slice := strings.Split(tmp, ";")
	if len(slice) == 0 {
		return fmt.Errorf("invalid raw cookie no ; found")
	}
	// first element is the cookie name and value
	cookie := strings.Split(slice[0], "=")
	if len(cookie) == 2 {
		c.Key = cookie[0]
		c.Value = cookie[1]
		return nil
	}
	return fmt.Errorf("invalid raw cookie: %s", c.Raw)
}

// GetAuthDataFromFile reads the auth data from file
func GetAuthDataFromFile(file string) (*Authx, error) {
	ext := filepath.Ext(file)
	if !generic.EqualsAny(ext, ".yml", ".yaml", ".json") {
		return nil, fmt.Errorf("invalid file extension: supported extensions are .yml,.yaml and .json got %s", ext)
	}
	bin, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if ext == ".yml" || ext == ".yaml" {
		return GetAuthDataFromYAML(bin)
	}
	return GetAuthDataFromJSON(bin)
}

// GetTemplatePathsFromSecretFile reads the template IDs from the secret file
func GetTemplatePathsFromSecretFile(file string) ([]string, error) {
	auth, err := GetAuthDataFromFile(file)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, dynamic := range auth.Dynamic {
		paths = append(paths, dynamic.TemplatePath)
	}
	return paths, nil
}

// GetAuthDataFromYAML reads the auth data from yaml
func GetAuthDataFromYAML(data []byte) (*Authx, error) {
	var auth Authx
	err := yaml.Unmarshal(data, &auth)
	if err != nil {
		errorErr := errkit.FromError(err)
		errorErr.Msgf("could not unmarshal yaml")
		return nil, errorErr
	}
	return &auth, nil
}

// GetAuthDataFromJSON reads the auth data from json
func GetAuthDataFromJSON(data []byte) (*Authx, error) {
	var auth Authx
	err := json.Unmarshal(data, &auth)
	if err != nil {
		errorErr := errkit.FromError(err)
		errorErr.Msgf("could not unmarshal json")
		return nil, errorErr
	}
	return &auth, nil
}

// ExtractAuthDataFromConfig extracts auth data from a YAML config or profile file
// by reading the top-level "secrets" key. Returns nil, nil if no "secrets" key
// is present. Extra/unknown fields in the config file are silently ignored.
func ExtractAuthDataFromConfig(configBytes []byte) (*Authx, error) {
	secretsBytes, err := ExtractSecretsYAMLFromConfig(configBytes)
	if err != nil || secretsBytes == nil {
		return nil, err
	}
	return GetAuthDataFromYAML(secretsBytes)
}

const (
	// maxDomainRegexLen is the maximum allowed length for a domain regex pattern.
	maxDomainRegexLen = 200
	// maxSecretsBlockSize is the maximum allowed size (in bytes) of the secrets block.
	maxSecretsBlockSize = 1 * 1024 * 1024 // 1 MB
)

// reNestedQuantifier detects regex patterns with nested quantifiers that can cause ReDoS
// (e.g., (a+)+, (.*)*, (a+)*).
var reNestedQuantifier = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*?{]`)

// validateDomainRegex checks a user-supplied domain regex pattern for safety
// before compilation: enforces a length cap and rejects nested quantifiers.
func validateDomainRegex(pattern string) error {
	if len(pattern) > maxDomainRegexLen {
		return fmt.Errorf("domain regex pattern too long (max %d chars): %s", maxDomainRegexLen, pattern)
	}
	if reNestedQuantifier.MatchString(pattern) {
		return fmt.Errorf("domain regex pattern contains nested quantifiers which may cause ReDoS: %s", pattern)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("invalid domain regex: %s", err)
	}
	return nil
}

// ExtractSecretsYAMLFromConfig extracts the raw YAML bytes of the "secrets"
// top-level key from a config or template profile file.
// Returns nil, nil if no "secrets" key is present.
func ExtractSecretsYAMLFromConfig(configBytes []byte) ([]byte, error) {
	if len(configBytes) > maxSecretsBlockSize {
		return nil, fmt.Errorf("config file too large (max %d bytes)", maxSecretsBlockSize)
	}
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(configBytes, &rawConfig); err != nil {
		return nil, errkit.Wrap(err, "could not unmarshal config yaml")
	}
	secretsRaw, ok := rawConfig["secrets"]
	if !ok || secretsRaw == nil {
		return nil, nil
	}
	switch v := secretsRaw.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			return nil, nil
		}
	case []interface{}:
		if len(v) == 0 {
			return nil, nil
		}
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
	}
	secretsBytes, err := yaml.Marshal(secretsRaw)
	if err != nil {
		return nil, errkit.Wrap(err, "could not re-marshal secrets block")
	}
	return secretsBytes, nil
}
