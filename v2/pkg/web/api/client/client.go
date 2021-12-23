package client

import (
	"github.com/projectdiscovery/retryablehttp-go"
)

// Client is a client for nuclei REST API
type Client struct {
	Templates Templates

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

	for _, opt := range opts {
		opt(c)
	}
	c.httpclient = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	return c
}

// // /targets endpoints
// apiGroup.GET("/targets", config.Server.GetTargets)
// apiGroup.POST("/targets", config.Server.AddTarget)
// apiGroup.PUT("/targets/:id", config.Server.UpdateTarget)
// apiGroup.DELETE("/targets/:id", config.Server.DeleteTarget)
// apiGroup.GET("/targets/:id", config.Server.GetTargetContents)
//
// // /settings endpoints
// apiGroup.GET("/settings", config.Server.GetSettings)
// apiGroup.POST("/settings", config.Server.SetSetting)
// apiGroup.GET("/settings/:name", config.Server.GetSettingByName)
// apiGroup.PUT("/settings/:name", config.Server.UpdateSettingByName)
//
// // /scans endpoints
// apiGroup.GET("/scans", config.Server.GetScans)
// apiGroup.POST("/scans", config.Server.AddScan)
// apiGroup.POST("/scans/progress", config.Server.GetScanProgress)
// apiGroup.GET("/scans/:id", config.Server.GetScan)
// apiGroup.PUT("/scans/:id", config.Server.UpdateScan)
// apiGroup.DELETE("/scans/:id", config.Server.DeleteScan)
// apiGroup.GET("/scans/:id/execute", config.Server.ExecuteScan)
// apiGroup.GET("/scans/:id/matches", config.Server.GetScanMatches)
// apiGroup.GET("/scans/:id/errors", config.Server.GetScanErrors)
//
// // /issues endpoints
// apiGroup.GET("/issues", config.Server.GetIssues)
// apiGroup.POST("/issues", config.Server.AddIssue)
// apiGroup.GET("/issues/:id", config.Server.GetIssue)
// apiGroup.PUT("/issues/:id", config.Server.UpdateIssue)
// apiGroup.DELETE("/issues/:id", config.Server.DeleteIssue)
