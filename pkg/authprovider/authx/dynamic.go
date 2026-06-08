package authx

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/errkit"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type LazyFetchSecret func(d *Dynamic) error

// fetchState holds the session state for a dynamic secret and makes it safe
// for concurrent use. It is stored as a pointer in Dynamic so that value copies
// (e.g. the one held inside DynamicAuthStrategy) share the same session.
//
// Unlike a plain sync.Once, this state machine supports re-authentication: the
// login flow can be re-run when the session goes stale (explicitly marked,
// detected from a response status, or after a configured refresh interval).
//
// Locking contract:
//   - Fetch/Refresh take the write lock while (re)running the login callback.
//   - The dynamic apply path (ApplyStrategies) holds the read lock while reading
//     the rendered secret, so request-time reads never race a concurrent re-auth.
type fetchState struct {
	mu        sync.RWMutex
	fetched   bool      // whether the login callback has completed at least once
	stale     bool      // whether the session must be re-authenticated on next fetch
	fetchedAt time.Time // time of the last successful/attempted fetch
	err       error     // error from the most recent fetch attempt
}

var (
	_ json.Unmarshaler = &Dynamic{}
)

// Dynamic is a struct for dynamic secret or credential
// these are high level secrets that take action to generate the actual secret
// ex: username and password are dynamic secrets, the actual secret is the token obtained
// after authenticating with the username and password
type Dynamic struct {
	*Secret      `yaml:",inline"`       // this is a static secret that will be generated after the dynamic secret is resolved
	Secrets      []*Secret              `yaml:"secrets"`
	TemplatePath string                 `json:"template" yaml:"template"`
	Variables    []KV                   `json:"variables" yaml:"variables"`
	Input        string                 `json:"input" yaml:"input"` // (optional) target for the dynamic secret
	Extracted    map[string]interface{} `json:"-" yaml:"-"`         // extracted values from the dynamic secret

	// RefreshInterval, when set (e.g. "15m"), causes the session to be
	// re-authenticated automatically once the rendered secret is older than the
	// interval. When empty/zero the session is fetched once and never expires by time.
	RefreshInterval string `json:"refresh-interval" yaml:"refresh-interval"`
	// ReauthStatusCodes is the set of HTTP response status codes that indicate
	// the session has expired (e.g. [401, 403]). When a matching response is
	// observed, the session is marked stale and re-authenticated before the next
	// request. When empty, response-triggered re-authentication is disabled.
	ReauthStatusCodes []int `json:"reauth-status-codes" yaml:"reauth-status-codes"`

	fetchCallback LazyFetchSecret `json:"-" yaml:"-"`
	// fetchState is shared across value-copies of Dynamic (e.g., inside DynamicAuthStrategy).
	// It must be initialized via Validate() before calling Fetch().
	fetchState *fetchState `json:"-" yaml:"-"`
	// refreshInterval is the parsed form of RefreshInterval.
	refreshInterval time.Duration `json:"-" yaml:"-"`
	// origSecret/origSecrets hold pristine copies of the secret templates (with
	// their {{var}} placeholders intact) captured before the first fetch. They are
	// used to re-render the secret on each re-authentication, since substitution
	// is destructive (placeholders are replaced with concrete values in place).
	origSecret  *Secret   `json:"-" yaml:"-"`
	origSecrets []*Secret `json:"-" yaml:"-"`
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
	if d.RefreshInterval != "" {
		dur, err := time.ParseDuration(d.RefreshInterval)
		if err != nil {
			return errkit.New("invalid refresh-interval %q for dynamic secret: %s", d.RefreshInterval, err)
		}
		if dur < 0 {
			return errkit.New("refresh-interval cannot be negative for dynamic secret")
		}
		d.refreshInterval = dur
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
//
// The provided callback is responsible for running the login flow and populating
// d.Extracted. The wrapper here renders the secret templates with the freshly
// extracted values. It snapshots the pristine secret templates on first use so
// that re-authentication can re-render them with new values (template
// substitution is destructive and would otherwise consume the placeholders).
func (d *Dynamic) SetLazyFetchCallback(callback LazyFetchSecret) {
	d.snapshotTemplates()
	d.fetchCallback = func(d *Dynamic) error {
		err := callback(d)
		if err != nil {
			return err
		}
		if len(d.Extracted) == 0 {
			return fmt.Errorf("no extracted values found for dynamic secret")
		}

		if d.Secret != nil {
			restoreSecretTemplate(d.Secret, d.origSecret)
			if err := d.applyValuesToSecret(d.Secret); err != nil {
				return err
			}
		}

		for i, secret := range d.Secrets {
			if i < len(d.origSecrets) {
				restoreSecretTemplate(secret, d.origSecrets[i])
			}
			if err := d.applyValuesToSecret(secret); err != nil {
				return err
			}
		}
		return nil
	}
}

// snapshotTemplates captures pristine copies of the secret templates (with their
// {{var}} placeholders intact) so they can be re-rendered on re-authentication.
func (d *Dynamic) snapshotTemplates() {
	if d.Secret != nil {
		d.origSecret = cloneSecretTemplate(d.Secret)
	}
	if len(d.Secrets) > 0 {
		d.origSecrets = make([]*Secret, len(d.Secrets))
		for i, secret := range d.Secrets {
			d.origSecrets[i] = cloneSecretTemplate(secret)
		}
	}
}

// cloneSecretTemplate deep-copies the templated fields of a secret so the
// original placeholders survive destructive in-place substitution.
func cloneSecretTemplate(s *Secret) *Secret {
	if s == nil {
		return nil
	}
	clone := *s
	clone.Headers = append([]KV(nil), s.Headers...)
	clone.Cookies = append([]Cookie(nil), s.Cookies...)
	clone.Params = append([]KV(nil), s.Params...)
	return &clone
}

// restoreSecretTemplate resets the templated fields of live back to the pristine
// template captured in snap, so the next substitution starts from placeholders.
func restoreSecretTemplate(live, snap *Secret) {
	if live == nil || snap == nil {
		return
	}
	live.Headers = append([]KV(nil), snap.Headers...)
	live.Cookies = append([]Cookie(nil), snap.Cookies...)
	live.Params = append([]KV(nil), snap.Params...)
	live.Username = snap.Username
	live.Password = snap.Password
	live.Token = snap.Token
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

	if d.fetchState == nil {
		return nil
	}
	d.fetchState.mu.RLock()
	defer d.fetchState.mu.RUnlock()
	if d.fetchState.err != nil {
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

// ApplyStrategies fetches (or re-authenticates) the session if needed and then
// applies each resolved auth strategy via the provided apply func while holding
// the read lock. This guarantees the rendered secret is never read at request
// time while a concurrent re-authentication is rewriting it.
func (d *Dynamic) ApplyStrategies(apply func(AuthStrategy)) {
	// Fetch (re)authenticates under the write lock if the session is missing or stale.
	_ = d.Fetch(false)
	if d.fetchState == nil {
		return
	}
	d.fetchState.mu.RLock()
	defer d.fetchState.mu.RUnlock()
	if d.fetchState.err != nil {
		return
	}
	if d.Secret != nil {
		if s := d.GetStrategy(); s != nil {
			apply(s)
		}
	}
	for _, secret := range d.Secrets {
		if s := secret.GetStrategy(); s != nil {
			apply(s)
		}
	}
}

// Fetch fetches the dynamic secret, (re)running the login flow when the session
// has not been fetched yet or has gone stale (explicitly marked, expired by
// refresh-interval, or invalidated by an observed response status code).
// if isFatal is true, it will stop the execution if the secret could not be fetched
func (d *Dynamic) Fetch(isFatal bool) error {
	if d.fetchState == nil {
		if isFatal {
			gologger.Fatal().Msgf("Could not fetch dynamic secret: Validate() must be called before Fetch()")
		}
		return errkit.New("dynamic secret not validated: call Validate() before Fetch()")
	}

	d.fetchState.mu.Lock()
	if !d.fetchState.fetched || d.isExpiredLocked() {
		d.runFetchLocked()
	}
	err := d.fetchState.err
	d.fetchState.mu.Unlock()

	if err != nil && isFatal {
		gologger.Fatal().Msgf("Could not fetch dynamic secret: %s\n", err)
	}
	return err
}

// Refresh forces an immediate re-authentication, re-running the login flow
// regardless of the current session state.
func (d *Dynamic) Refresh(isFatal bool) error {
	if d.fetchState == nil {
		if isFatal {
			gologger.Fatal().Msgf("Could not refresh dynamic secret: Validate() must be called before Refresh()")
		}
		return errkit.New("dynamic secret not validated: call Validate() before Refresh()")
	}

	d.fetchState.mu.Lock()
	d.fetchState.fetched = false
	d.fetchState.stale = false
	d.runFetchLocked()
	err := d.fetchState.err
	d.fetchState.mu.Unlock()

	if err != nil && isFatal {
		gologger.Fatal().Msgf("Could not refresh dynamic secret: %s\n", err)
	}
	return err
}

// MarkStale marks the session for re-authentication on the next fetch. It is
// cheap and does not perform any network I/O; the actual re-auth happens on the
// next Fetch/ApplyStrategies call so it never runs in a response-handling path.
func (d *Dynamic) MarkStale() {
	if d.fetchState == nil {
		return
	}
	d.fetchState.mu.Lock()
	d.fetchState.stale = true
	d.fetchState.mu.Unlock()
}

// NotifyResponse inspects a response and, if its status code is configured as a
// session-expiry signal, marks the session stale so it is re-authenticated
// before the next request. It returns true if re-authentication was triggered.
func (d *Dynamic) NotifyResponse(statusCode int) bool {
	if d.fetchState == nil || !d.shouldReauthOnStatus(statusCode) {
		return false
	}
	// Only mark stale if we actually have an established session to refresh.
	d.fetchState.mu.RLock()
	fetched := d.fetchState.fetched
	d.fetchState.mu.RUnlock()
	if !fetched {
		return false
	}
	d.MarkStale()
	return true
}

// IsExpired reports whether the session is currently considered expired/stale.
func (d *Dynamic) IsExpired() bool {
	if d.fetchState == nil {
		return false
	}
	d.fetchState.mu.RLock()
	defer d.fetchState.mu.RUnlock()
	return d.isExpiredLocked()
}

// runFetchLocked runs the login callback. The caller must hold the write lock.
func (d *Dynamic) runFetchLocked() {
	if d.fetchCallback == nil {
		d.fetchState.err = errkit.New("dynamic secret fetch callback not set: call SetLazyFetchCallback() before Fetch()")
		return
	}
	d.fetchState.err = d.fetchCallback(d)
	d.fetchState.fetched = true
	d.fetchState.stale = false
	d.fetchState.fetchedAt = time.Now()
}

// isExpiredLocked reports whether the session needs re-authentication. The
// caller must hold at least the read lock.
func (d *Dynamic) isExpiredLocked() bool {
	if !d.fetchState.fetched {
		return false
	}
	if d.fetchState.stale {
		return true
	}
	if d.refreshInterval > 0 && time.Since(d.fetchState.fetchedAt) > d.refreshInterval {
		return true
	}
	return false
}

// shouldReauthOnStatus reports whether the given status code is configured as a
// session-expiry signal.
func (d *Dynamic) shouldReauthOnStatus(statusCode int) bool {
	for _, code := range d.ReauthStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

// Error returns the error if any
func (d *Dynamic) Error() error {
	if d.fetchState == nil {
		return nil
	}
	d.fetchState.mu.RLock()
	defer d.fetchState.mu.RUnlock()
	return d.fetchState.err
}
