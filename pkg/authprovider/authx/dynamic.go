package authx

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	errorutil "github.com/projectdiscovery/utils/errors"
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
	Secret        `yaml:",inline"`       // this is a static secret that will be generated after the dynamic secret is resolved
	TemplateID    string                 `json:"template-id" yaml:"template-id"`
	TemplatePath  string                 `json:"template-path" yaml:"template-path"`
	Variables     []KV                   `json:"variables" yaml:"variables"`
	extracted     map[string]interface{} `json:"-" yaml:"-"` // extracted values from the dynamic secret
	fetchCallback LazyFetchSecret        `json:"-" yaml:"-"`
	m             *sync.Mutex            `json:"-" yaml:"-"` // mutex for lazy fetch
	fetched       bool                   `json:"-" yaml:"-"` // flag to check if the secret has been fetched
	error         error                  `json:"-" yaml:"-"` // error if any
}

func (d *Dynamic) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	var s Secret
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d.Secret = s
	return nil
}

// Validate validates the dynamic secret
func (d *Dynamic) Validate() error {
	d.m = &sync.Mutex{}
	if d.TemplateID == "" && d.TemplatePath == "" {
		return errorutil.New("template-id or template-path is required for dynamic secret")
	}
	if d.TemplateID != "" && d.TemplatePath != "" {
		return errorutil.New("only one of template-id or template-path is allowed for dynamic secret")
	}
	if len(d.Variables) == 0 {
		return errorutil.New("variables are required for dynamic secret")
	}
	d.skipCookieParse = true // skip cookie parsing in dynamic secrets during validation
	if err := d.Secret.Validate(); err != nil {
		return err
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
		if len(d.extracted) == 0 {
			return fmt.Errorf("no extracted values found for dynamic secret")
		}

		// evaluate headers
		for i, header := range d.Headers {
			if strings.Contains(header.Value, "{{") {
				header.Value = replacer.Replace(header.Value, d.extracted)
			}
			if strings.Contains(header.Key, "{{") {
				header.Key = replacer.Replace(header.Key, d.extracted)
			}
			d.Headers[i] = header
		}

		// evaluate cookies
		for i, cookie := range d.Cookies {
			if strings.Contains(cookie.Value, "{{") {
				cookie.Value = replacer.Replace(cookie.Value, d.extracted)
			}
			if strings.Contains(cookie.Key, "{{") {
				cookie.Key = replacer.Replace(cookie.Key, d.extracted)
			}
			if strings.Contains(cookie.Raw, "{{") {
				cookie.Raw = replacer.Replace(cookie.Raw, d.extracted)
			}
			d.Cookies[i] = cookie
		}

		// evaluate query params
		for i, query := range d.Params {
			if strings.Contains(query.Value, "{{") {
				query.Value = replacer.Replace(query.Value, d.extracted)
			}
			if strings.Contains(query.Key, "{{") {
				query.Key = replacer.Replace(query.Key, d.extracted)
			}
			d.Params[i] = query
		}

		// check username, password and token
		if strings.Contains(d.Username, "{{") {
			d.Username = replacer.Replace(d.Username, d.extracted)
		}
		if strings.Contains(d.Password, "{{") {
			d.Password = replacer.Replace(d.Password, d.extracted)
		}
		if strings.Contains(d.Token, "{{") {
			d.Token = replacer.Replace(d.Token, d.extracted)
		}

		// now attempt to parse the cookies
		d.skipCookieParse = false
		for i, cookie := range d.Cookies {
			if cookie.Raw != "" {
				if err := cookie.Parse(); err != nil {
					return fmt.Errorf("[%s] invalid raw cookie in cookiesAuth: %s", d.getIdentifier(), err)
				}
				d.Cookies[i] = cookie
			}
		}
		return nil
	}
}

func (d *Dynamic) getIdentifier() string {
	if d.TemplateID != "" {
		return d.TemplateID
	}
	return d.TemplatePath
}

// GetStrategy returns the auth strategy for the dynamic secret
func (d *Dynamic) GetStrategy() AuthStrategy {
	if !d.fetched {
		d.Fetch()
	}
	if d.error != nil {
		gologger.Error().Msgf("Could not fetch dynamic secret: %s\n", d.error)
		return nil
	}
	return d.Secret.GetStrategy()
}

// Fetch fetches the dynamic secret
func (d *Dynamic) Fetch() {
	d.m.Lock()
	defer d.m.Unlock()
	if d.fetched {
		return
	}
	d.error = d.fetchCallback(d)
}

// Error returns the error if any
func (d *Dynamic) Error() error {
	return d.error
}
