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
	TemplatePath  string                 `json:"template" yaml:"template"`
	Variables     []KV                   `json:"variables" yaml:"variables"`
	Input         string                 `json:"input" yaml:"input"` // (optional) target for the dynamic secret
	Extracted     map[string]interface{} `json:"-" yaml:"-"`         // extracted values from the dynamic secret
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
	if d.TemplatePath == "" {
		return errorutil.New(" template-path is required for dynamic secret")
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
		if len(d.Extracted) == 0 {
			return fmt.Errorf("no extracted values found for dynamic secret")
		}

		// evaluate headers
		for i, header := range d.Headers {
			if strings.Contains(header.Value, "{{") {
				header.Value = replacer.Replace(header.Value, d.Extracted)
			}
			if strings.Contains(header.Key, "{{") {
				header.Key = replacer.Replace(header.Key, d.Extracted)
			}
			d.Headers[i] = header
		}

		// evaluate cookies
		for i, cookie := range d.Cookies {
			if strings.Contains(cookie.Value, "{{") {
				cookie.Value = replacer.Replace(cookie.Value, d.Extracted)
			}
			if strings.Contains(cookie.Key, "{{") {
				cookie.Key = replacer.Replace(cookie.Key, d.Extracted)
			}
			if strings.Contains(cookie.Raw, "{{") {
				cookie.Raw = replacer.Replace(cookie.Raw, d.Extracted)
			}
			d.Cookies[i] = cookie
		}

		// evaluate query params
		for i, query := range d.Params {
			if strings.Contains(query.Value, "{{") {
				query.Value = replacer.Replace(query.Value, d.Extracted)
			}
			if strings.Contains(query.Key, "{{") {
				query.Key = replacer.Replace(query.Key, d.Extracted)
			}
			d.Params[i] = query
		}

		// check username, password and token
		if strings.Contains(d.Username, "{{") {
			d.Username = replacer.Replace(d.Username, d.Extracted)
		}
		if strings.Contains(d.Password, "{{") {
			d.Password = replacer.Replace(d.Password, d.Extracted)
		}
		if strings.Contains(d.Token, "{{") {
			d.Token = replacer.Replace(d.Token, d.Extracted)
		}

		// now attempt to parse the cookies
		d.skipCookieParse = false
		for i, cookie := range d.Cookies {
			if cookie.Raw != "" {
				if err := cookie.Parse(); err != nil {
					return fmt.Errorf("[%s] invalid raw cookie in cookiesAuth: %s", d.TemplatePath, err)
				}
				d.Cookies[i] = cookie
			}
		}
		return nil
	}
}

// GetStrategy returns the auth strategy for the dynamic secret
func (d *Dynamic) GetStrategy() AuthStrategy {
	if !d.fetched {
		_ = d.Fetch(true)
	}
	if d.error != nil {
		return nil
	}
	return d.Secret.GetStrategy()
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
