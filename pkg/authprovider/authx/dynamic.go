package authx

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/errkit"
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
	*Secret       `yaml:",inline"` // this is a static secret that will be generated after the dynamic secret is resolved
	Secrets       []*Secret        `yaml:"secrets"`
	TemplatePath  string           `json:"template" yaml:"template"`
	Variables     []KV             `json:"variables" yaml:"variables"`
	Input         string           `json:"input" yaml:"input"` // (optional) target for the dynamic secret
	Extracted     map[string]interface{} `json:"-" yaml:"-"`   // extracted values from the dynamic secret
	fetchCallback LazyFetchSecret  `json:"-" yaml:"-"`
	once          *atomic.Pointer[*sync.Once] `json:"-" yaml:"-"` // stores *sync.Once, allows retry on failure
	fetched       *atomic.Bool                `json:"-" yaml:"-"` // atomic flag to check if the secret has been fetched
	mu            sync.RWMutex                `json:"-" yaml:"-"` // protects err field
	err           error                       `json:"-" yaml:"-"` // error if any
}

// getOnce returns the current sync.Once instance, creating a new one if needed.
// It uses double-checked locking pattern for thread-safe lazy initialization
// and is safe for concurrent use. It also handles the case where Validate()
// was not called by lazily initializing the atomic.Pointer.
func (d *Dynamic) getOnce() *sync.Once {
	// Handle case where Validate() was not called
	if d.once == nil {
		d.once = &atomic.Pointer[*sync.Once]{}
	}
	// Fast path - check if already initialized
	ptr := d.once.Load()
	if ptr != nil {
		return *ptr
	}
	// Slow path - create new sync.Once
	once := &sync.Once{}
	// Try to store - if another goroutine beat us, use theirs
	if !d.once.CompareAndSwap(nil, &once) {
		// Someone else stored, use their value
		return *d.once.Load()
	}
	return once
}

// resetOnce atomically replaces the sync.Once with a new instance,
// allowing the fetch operation to be retried. This is called when
// fetch fails to enable retry on the next call.
func (d *Dynamic) resetOnce() {
	// Atomically swap with a new sync.Once
	once := &sync.Once{}
	d.once.Store(&once)
}

// GetDomainAndDomainRegex returns all domains and domain regexes from the dynamic
// secret and its embedded secrets. It deduplicates the results before returning.
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

// UnmarshalJSON implements json.Unmarshaler for Dynamic.
// It handles the inline Secret embedding correctly during JSON unmarshalling.
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
	d.once = &atomic.Pointer[*sync.Once]{}
	once := &sync.Once{}
	d.once.Store(&once)
	d.fetched = &atomic.Bool{}
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

// SetLazyFetchCallback sets the lazy fetch callback for the dynamic secret.
// The callback will be invoked when Fetch() or GetStrategies() is first called.
func (d *Dynamic) SetLazyFetchCallback(callback LazyFetchSecret) {
	d.fetchCallback = callback
}

// applyValuesToSecret replaces template variables (e.g., {{token}}) in the
// secret's headers, cookies, params, username, password, and token fields
// with the corresponding values from the Dynamic's Extracted map.
// It also parses raw cookies after template replacement.
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

// fetchAndHydrate executes the fetch callback and hydrates all secrets with
// the extracted values in a single atomic operation. This method MUST be called
// under sync.Once guard to ensure thread-safe fetch-and-hydrate semantics.
// On error, the once guard is reset to allow retry on the next call.
func (d *Dynamic) fetchAndHydrate() {
	d.mu.Lock()
	// Check if fetchCallback is nil before calling
	if d.fetchCallback == nil {
		d.err = fmt.Errorf("fetchCallback is not set for dynamic secret")
		d.mu.Unlock()
		// Reset once to allow retry on next call
		d.resetOnce()
		return
	}
	d.err = d.fetchCallback(d)
	if d.err != nil {
		d.mu.Unlock()
		// Reset once to allow retry on next call
		d.resetOnce()
		return
	}
	if len(d.Extracted) == 0 {
		d.err = fmt.Errorf("no extracted values found for dynamic secret")
		d.mu.Unlock()
		// Reset once to allow retry on next call
		d.resetOnce()
		return
	}

	if d.Secret != nil {
		if err := d.applyValuesToSecret(d.Secret); err != nil {
			d.err = err
			d.mu.Unlock()
			// Reset once to allow retry on next call
			d.resetOnce()
			return
		}
	}

	for _, secret := range d.Secrets {
		if err := d.applyValuesToSecret(secret); err != nil {
			d.err = err
			d.mu.Unlock()
			// Reset once to allow retry on next call
			d.resetOnce()
			return
		}
	}
	d.mu.Unlock()

	// Mark as fetched successfully (only after successful fetch and hydration)
	// Check for nil to handle case where Validate() was not called
	if d.fetched != nil {
		d.fetched.Store(true)
	}
}

// GetStrategies returns the auth strategies for the dynamic secret.
// It ensures that fetch and hydrate are called exactly once, and all concurrent
// callers block until the operation completes. If the fetch fails, it returns nil.
// The once guard is reset on failure to allow retry on the next call.
func (d *Dynamic) GetStrategies() []AuthStrategy {
	// Use sync.Once to ensure fetch and hydrate are called exactly once and all callers block until complete
	d.getOnce().Do(d.fetchAndHydrate)

	// If fetch failed, return nil strategies
	d.mu.RLock()
	hasError := d.err != nil
	d.mu.RUnlock()
	if hasError {
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

// Fetch triggers the lazy fetch of the dynamic secret and returns any error.
// It ensures fetch and hydrate are called exactly once, and all concurrent
// callers block until the operation completes. On error, the once guard is
// reset to allow retry on the next call.
func (d *Dynamic) Fetch() error {
	// Use sync.Once to ensure fetch and hydrate are called exactly once and all callers block until complete
	d.getOnce().Do(d.fetchAndHydrate)

	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.err
}

// Error returns the error from the last fetch operation, if any.
// It is safe for concurrent use.
func (d *Dynamic) Error() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.err
}

// Reset resets the fetch state, allowing a fresh fetch on next call
// This is useful when you want to force a re-fetch of the dynamic secret
// Call Validate() again after Reset() if you want to ensure the secret is still valid
func (d *Dynamic) Reset() {
	once := &sync.Once{}
	d.once.Store(&once)
	if d.fetched != nil {
		d.fetched.Store(false)
	}
	d.mu.Lock()
	d.err = nil
	d.Extracted = nil
	d.mu.Unlock()
}

// IsFetched returns true if the dynamic secret has been successfully fetched
func (d *Dynamic) IsFetched() bool {
	if d.fetched == nil {
		return false
	}
	return d.fetched.Load()
}
