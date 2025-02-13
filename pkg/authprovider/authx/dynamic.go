package authx

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	errorutil "github.com/projectdiscovery/utils/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type LazyFetchSecret func(d *Dynamic) error

var (
	_ json.Unmarshaler = &Dynamic{}
)

// Dynamic is a struct for dynamic secret or credential
// these are high level secrets that take action to generate the actual secret
// ex: username and password are dynamic secrets, the actual secret is the token obtained
// after authenticating with the username and password
type Dynamic struct {
	*Secret       `yaml:",inline"`       // this is a static secret that will be generated after the dynamic secret is resolved
	Secrets       []*Secret              `yaml:"secrets"`
	TemplatePath  string                 `json:"template" yaml:"template"`
	Variables     []KV                   `json:"variables" yaml:"variables"`
	Input         string                 `json:"input" yaml:"input"` // (optional) target for the dynamic secret
	Extracted     map[string]interface{} `json:"-" yaml:"-"`         // extracted values from the dynamic secret
	fetchCallback LazyFetchSecret        `json:"-" yaml:"-"`
	m             *sync.Mutex            `json:"-" yaml:"-"` // mutex for lazy fetch
	fetched       bool                   `json:"-" yaml:"-"` // flag to check if the secret has been fetched
	error         error                  `json:"-" yaml:"-"` // error if any
}

func (d *Dynamic) GetDomainAndDomainRegex() ([]string, []string) {
	var domains []string
	var domainRegex []string
	for _, secret := range d.Secrets {
		domains = append(domains, secret.Domains...)
		domainRegex = append(domainRegex, secret.DomainsRegex...)
	}
	if d.Secret != nil {
		domains = append(domains, d.Secret.Domains...)
		domainRegex = append(domainRegex, d.Secret.DomainsRegex...)
	}
	uniqueDomains := sliceutil.Dedupe(domains)
	uniqueDomainRegex := sliceutil.Dedupe(domainRegex)
	return uniqueDomains, uniqueDomainRegex
}

func (d *Dynamic) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	var s Secret
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d.Secret = &s
	return nil
}

// Validate validates the dynamic secret
func (d *Dynamic) Validate() error {
	d.m = &sync.Mutex{}
	if d.TemplatePath == "" {
		return errorutil.New(" template-path is required for dynamic secret")
	}
	if len(d.Variables) == 0 {
		return errorutil.New("variables are required for dynamic secret")
	}

	if d.Secret != nil {
		d.Secret.skipCookieParse = true // skip cookie parsing in dynamic secrets during validation
		if err := d.Secret.Validate(); err != nil {
			return err
		}
	}
	for _, secret := range d.Secrets {
		secret.skipCookieParse = true
		if err := secret.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// SetLazyFetchCallback sets the lazy fetch callback for the dynamic secret
func (d *Dynamic) SetLazyFetchCallback(callback LazyFetchSecret) {
	d.fetchCallback = func(d *Dynamic) error {
		err := callback(d)
		d.fetched = true
		if err != nil {
			d.error = err
			return err
		}
		if len(d.Extracted) == 0 {
			return fmt.Errorf("no extracted values found for dynamic secret")
		}

		if d.Secret != nil {
			if err := d.applyValuesToSecret(d.Secret); err != nil {
				return err
			}
		}

		for _, secret := range d.Secrets {
			if err := d.applyValuesToSecret(secret); err != nil {
				return err
			}
		}
		return nil
	}
}

func (d *Dynamic) applyValuesToSecret(secret *Secret) error {
	// evaluate headers
	for i, header := range secret.Headers {
		if strings.Contains(header.Value, "{{") {
			header.Value = replacer.Replace(header.Value, d.Extracted)
		}
		if strings.Contains(header.Key, "{{") {
			header.Key = replacer.Replace(header.Key, d.Extracted)
		}
		secret.Headers[i] = header
	}

	// evaluate cookies
	for i, cookie := range secret.Cookies {
		if strings.Contains(cookie.Value, "{{") {
			cookie.Value = replacer.Replace(cookie.Value, d.Extracted)
		}
		if strings.Contains(cookie.Key, "{{") {
			cookie.Key = replacer.Replace(cookie.Key, d.Extracted)
		}
		if strings.Contains(cookie.Raw, "{{") {
			cookie.Raw = replacer.Replace(cookie.Raw, d.Extracted)
		}
		secret.Cookies[i] = cookie
	}

	// evaluate query params
	for i, query := range secret.Params {
		if strings.Contains(query.Value, "{{") {
			query.Value = replacer.Replace(query.Value, d.Extracted)
		}
		if strings.Contains(query.Key, "{{") {
			query.Key = replacer.Replace(query.Key, d.Extracted)
		}
		secret.Params[i] = query
	}

	// check username, password and token
	if strings.Contains(secret.Username, "{{") {
		secret.Username = replacer.Replace(secret.Username, d.Extracted)
	}
	if strings.Contains(secret.Password, "{{") {
		secret.Password = replacer.Replace(secret.Password, d.Extracted)
	}
	if strings.Contains(secret.Token, "{{") {
		secret.Token = replacer.Replace(secret.Token, d.Extracted)
	}

	// now attempt to parse the cookies
	secret.skipCookieParse = false
	for i, cookie := range secret.Cookies {
		if cookie.Raw != "" {
			if err := cookie.Parse(); err != nil {
				return fmt.Errorf("[%s] invalid raw cookie in cookiesAuth: %s", d.TemplatePath, err)
			}
			secret.Cookies[i] = cookie
		}
	}
	return nil
}

// GetStrategy returns the auth strategies for the dynamic secret
func (d *Dynamic) GetStrategies() []AuthStrategy {
	if !d.fetched {
		_ = d.Fetch(true)
	}
	if d.error != nil {
		return nil
	}
	var strategies []AuthStrategy
	if d.Secret != nil {
		strategies = append(strategies, d.Secret.GetStrategy())
	}
	for _, secret := range d.Secrets {
		strategies = append(strategies, secret.GetStrategy())
	}
	return strategies
}

// Fetch fetches the dynamic secret
// if isFatal is true, it will stop the execution if the secret could not be fetched
func (d *Dynamic) Fetch(isFatal bool) error {
	d.m.Lock()
	defer d.m.Unlock()
	if d.fetched {
		return nil
	}
	d.error = d.fetchCallback(d)
	if d.error != nil && isFatal {
		gologger.Fatal().Msgf("Could not fetch dynamic secret: %s\n", d.error)
	}
	return d.error
}

// Error returns the error if any
func (d *Dynamic) Error() error {
	return d.error
}
