package client

import (
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
)

// Client is a client for nuclei REST API
type Client struct {
	Templates Templates
	Targets   Targets
	Settings  Settings
	Scans     Scans
	Issues    Issues

	username string
	password string
	baseURL  string

	httpclient *retryablehttp.Client
}

// Option represents an options for the API Client
type Option func(*Client)

// WithBasicAuth returns a client with basic auth parameters set
func WithBasicAuth(username, password string) Option {
	return func(c *Client) {
		c.username = username
		c.password = password
	}
}

// WithBaseURL returns a client with custom baseURL
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// New returns a new nuclei REST API Client
func New(opts ...Option) *Client {
	const defaultBaseURL = "http://localhost:8822/api/v1"

	c := &Client{baseURL: defaultBaseURL}
	c.Templates = &TemplatesService{Client: c}
	c.Targets = &TargetsService{Client: c}
	c.Settings = &SettingsService{Client: c}
	c.Scans = &ScansService{Client: c}
	c.Issues = &IssuesService{Client: c}

	for _, opt := range opts {
		opt(c)
	}
	clientOpts := retryablehttp.DefaultOptionsSingle
	clientOpts.RetryMax = 0
	clientOpts.Timeout = 15 * time.Second
	c.httpclient = retryablehttp.NewClient(clientOpts)
	return c
}
