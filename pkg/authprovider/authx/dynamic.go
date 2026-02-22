package authx

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/errkit"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type LazyFetchSecret func(d *Dynamic, done <-chan struct{}) error

var (
	_ json.Unmarshaler = &Dynamic{}
)

var dynamicFetchTimeout = 30 * time.Second

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
	fetched       *atomic.Bool           `json:"-" yaml:"-"` // atomic flag to check if the secret has been fetched
	fetching      *atomic.Bool           `json:"-" yaml:"-"` // atomic flag to prevent recursive fetch calls
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
	d.fetched = &atomic.Bool{}
	d.fetching = &atomic.Bool{}
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
	d.fetchCallback = func(d *Dynamic, done <-chan struct{}) error {
		err := callback(d, done)
		if err != nil {
			return err
		}
		select {
		case <-done:
			return errkit.New("could not fetch dynamic secret: timeout waiting for fetch callback")
		default:
		}
		if len(d.Extracted) == 0 {
			return fmt.Errorf("no extracted values found for dynamic secret")
		}

		if d.Secret != nil {
			if err := d.applyValuesToSecret(d.Secret); err != nil {
				return err
			}
		}

		select {
		case <-done:
			return errkit.New("could not fetch dynamic secret: timeout waiting for fetch callback")
		default:
		}

		for _, secret := range d.Secrets {
			if err := d.applyValuesToSecret(secret); err != nil {
				return err
			}

			select {
			case <-done:
				return errkit.New("could not fetch dynamic secret: timeout waiting for fetch callback")
			default:
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
	if d.fetched.Load() {
		if d.error != nil {
			return nil
		}
	} else {
		// Try to fetch if not already fetched
		_ = d.Fetch(true)
	}

	if d.error != nil {
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
	if d.fetched.Load() {
		return d.error
	}

	// Try to set fetching flag atomically.
	if !d.fetching.CompareAndSwap(false, true) {
		// Another goroutine is fetching this secret. Wait until it finishes so
		// concurrent template execution can proceed with resolved auth values.
		timeout := time.NewTimer(dynamicFetchTimeout)
		defer timeout.Stop()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for !d.fetched.Load() {
			select {
			case <-timeout.C:
				return errkit.New("could not fetch dynamic secret: timeout waiting for fetch callback")
			case <-ticker.C:
			}
		}
		return d.error
	}

	done := make(chan struct{})
	var doneOnce sync.Once
	closeDone := func() {
		doneOnce.Do(func() {
			close(done)
		})
	}

	result := make(chan error, 1)
	go func() {
		var err error
		defer func() {
			if r := recover(); r != nil {
				err = errkit.Newf("fetch callback panicked: %v", r)
			}
			result <- err
		}()
		err = d.fetchCallback(d, done)
		closeDone()
	}()

	fetchTimer := time.NewTimer(dynamicFetchTimeout)
	var err error
	select {
	case resultErr := <-result:
		if !fetchTimer.Stop() {
			select {
			case <-fetchTimer.C:
			default:
			}
		}
		err = resultErr
	case <-fetchTimer.C:
		closeDone()
		err = errkit.New("could not fetch dynamic secret: timeout waiting for fetch callback")
	}

	d.error = err
	d.fetched.Store(true)
	d.fetching.Store(false)

	if d.error != nil && isFatal {
		gologger.Fatal().Msgf("Could not fetch dynamic secret: %s\n", d.error)
	}
	return d.error
}

// Error returns the error if any
func (d *Dynamic) Error() error {
	return d.error
}
