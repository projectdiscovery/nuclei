package authx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
	"gopkg.in/yaml.v3"
)

type AuthType string

const (
	BasicAuth       AuthType = "BasicAuth"
	BearerTokenAuth AuthType = "BearerToken"
	HeadersAuth     AuthType = "Headers"
	CookiesAuth     AuthType = "Cookies"
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
	ID      string   `json:"id" yaml:"id"`
	Secrets []Secret `json:"secrets" yaml:"secrets"`
}

// Secret is a struct for secret or credential
type Secret struct {
	Type         string   `json:"type" yaml:"type"`
	Domains      []string `json:"domains" yaml:"domains"`
	DomainsRegex []string `json:"domains-regex" yaml:"domains-regex"`
	Headers      []KV     `json:"headers" yaml:"headers"`
	Cookies      []KV     `json:"cookies" yaml:"cookies"`
	Params       []KV     `json:"params" yaml:"params"`
	Username     string   `json:"username" yaml:"username"` // can be either email or username
	Password     string   `json:"password" yaml:"password"`
	Token        string   `json:"token" yaml:"token"` // Bearer Auth token
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
	if stringsutil.EqualFoldAny(s.Type, SupportedAuthTypes()...) {
		return fmt.Errorf("invalid type: %s", s.Type)
	}
	if len(s.Domains) == 0 && len(s.DomainsRegex) == 0 {
		return fmt.Errorf("domains or domains-regex cannot be empty")
	}
	if len(s.DomainsRegex) > 0 {
		for _, domain := range s.DomainsRegex {
			_, err := regexp.Compile(domain)
			if err != nil {
				return fmt.Errorf("invalid domain regex: %s", domain)
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
	Key   string `json:"key" yaml:"key"`
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

// GetAuthDataFromFile reads the auth data from file
func GetAuthDataFromFile(file string) (*Authx, error) {
	if filepath.Ext(file) != ".yml" && filepath.Ext(file) != ".json" {
		return nil, fmt.Errorf("invalid file extension: supported extensions are .yml and .json")
	}
	bin, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if filepath.Ext(file) == ".yml" {
		return GetAuthDataFromYAML(bin)
	}
	return GetAuthDataFromJSON(bin)
}

// GetAuthDataFromYAML reads the auth data from yaml
func GetAuthDataFromYAML(data []byte) (*Authx, error) {
	var auth Authx
	err := yaml.Unmarshal(data, &auth)
	if err != nil {
		return nil, err
	}
	return &auth, nil
}

// GetAuthDataFromJSON reads the auth data from json
func GetAuthDataFromJSON(data []byte) (*Authx, error) {
	var auth Authx
	err := json.Unmarshal(data, &auth)
	if err != nil {
		return nil, err
	}
	return &auth, nil
}
