package authx

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/errkit"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type LazyFetchSecret func(d *Dynamic) error

// fetchState holds the sync.Once and error for thread-safe fetching.
// This is stored as a pointer in Dynamic so that value copies share the same state.
type fetchState struct {
	once sync.Once
	err  error
}

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
	// fetchState is shared across value-copies of Dynamic (e.g., inside DynamicAuthStrategy).
	// It must be initialized via Validate() before calling Fetch().
	fetchState *fetchState `json:"-" yaml:"-"`
}

func (d *Dynamic) GetDomainAndDomainRegex() ([]string, []string) {
	var domains []string
	var domainRegex []string
	for _, secret := range d.Secrets {
		domains = append(domains, secret.Domains...)
		domainRegex = append(domainRegex, secret.DomainsRegex...)
	}
	if d.Secret != nil {
		domains = append(domains, d.Domains...)
		domainRegex = append(domainRegex, d.DomainsRegex...)
	}
	uniqueDomains := sliceutil.Dedupe(domains)
	uniqueDomainRegex := sliceutil.Dedupe(domainRegex)
	return uniqueDomains, uniqueDomainRegex
}

func (d *Dynamic) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errkit.New("cannot unmarshal into nil Dynamic struct")
	}

	// Use an alias type (auxiliary) to avoid a recursive call in this method.
	type Alias Dynamic

	// If d.Secret was nil, json.Unmarshal will allocate a new Secret object
	// and populate it from the top level JSON fields.
	if err := json.Unmarshal(data, (*Alias)(d)); err != nil {
		return err
	}

	return nil
}

// Validate validates the dynamic secret
func (d *Dynamic) Validate() error {
	// NOTE: Validate() must not be called concurrently with Fetch()/GetStrategies().
	// Re-validating resets fetch state and allows re-fetching.
	d.fetchState = &fetchState{}
	if d.TemplatePath == "" {
		return errkit.New(" template-path is required for dynamic secret")
	}
	if len(d.Variables) == 0 {
		return errkit.New("variables are required for dynamic secret")
	}

	if d.Secret != nil {
		d.skipCookieParse = true // skip cookie parsing in dynamic secrets during validation
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
		if err != nil {
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

// GetStrategies returns the auth strategies for the dynamic secret
func (d *Dynamic) GetStrategies() []AuthStrategy {
	// Ensure fetch has completed before returning strategies.
	// Fetch errors are treated as non-fatal here so a failed dynamic auth fetch
	// does not terminate the entire scan process.
	_ = d.Fetch(false)

	if d.fetchState != nil && d.fetchState.err != nil {
		return nil
	}
	var strategies []AuthStrategy
	if d.Secret != nil {
		strategies = append(strategies, d.GetStrategy())
	}
	for _, secret := range d.Secrets {
		strategies = append(strategies, secret.GetStrategy())
	}
	return strategies
}

// Fetch fetches the dynamic secret
// if isFatal is true, it will stop the execution if the secret could not be fetched
func (d *Dynamic) Fetch(isFatal bool) error {
	if d.fetchState == nil {
		if isFatal {
			gologger.Fatal().Msgf("Could not fetch dynamic secret: Validate() must be called before Fetch()")
		}
		return errkit.New("dynamic secret not validated: call Validate() before Fetch()")
	}

	d.fetchState.once.Do(func() {
		if d.fetchCallback == nil {
			d.fetchState.err = errkit.New("dynamic secret fetch callback not set: call SetLazyFetchCallback() before Fetch()")
			return
		}
		d.fetchState.err = d.fetchCallback(d)
	})

	if d.fetchState.err != nil && isFatal {
		gologger.Fatal().Msgf("Could not fetch dynamic secret: %s\n", d.fetchState.err)
	}
	return d.fetchState.err
}

// Error returns the error if any
func (d *Dynamic) Error() error {
	if d.fetchState == nil {
		return nil
	}
	return d.fetchState.err
}
