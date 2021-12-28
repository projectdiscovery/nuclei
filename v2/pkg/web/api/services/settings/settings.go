package settings

import (
	"context"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"gopkg.in/yaml.v3"
)

// Settings contains internal nuclei engine configuration settings
// for nuclei REST API interface
type Settings struct {
	// execute a subset of templates that contain the provided tags
	Tags []string `yaml:"tags"`
	// tags from the default deny list that permit executing more intrusive templates
	IncludeTags []string `yaml:"include-tags"`
	// exclude templates with the provided tags
	ExcludeTags []string `yaml:"exclude-tags"`
	// templates to be executed even if they are excluded either by default or configuration
	IncludeTemplates []string `yaml:"include-templates"`
	// template or template directory paths to exclude
	ExcludeTemplates []string `yaml:"exclude-templates"`
	// templates to run based on severity. possible values: info, low, medium, high, critical
	Impact []string `yaml:"impact"`
	// execute templates that are (co-)created by the specified authors
	Authors []string `yaml:"authors"`
	// nuclei reporting module configuration file
	ReportConfig string `yaml:"report-config"`
	// custom headers in header:value format
	Header map[string]string `yaml:"headers"`
	// custom vars in var=value format
	Vars map[string]string `yaml:"vars"`
	// file containing resolver list for nuclei
	Resolvers string `yaml:"resolvers"`
	// use system dns resolving as error fallback
	SystemResolvers bool `yaml:"system-resolvers"`
	// enable environment variables support
	EnvironmentVars bool `yaml:"env-vars"`
	// do not use interactsh server for blind interaction polling
	NoInteractsh bool `yaml:"no-interactsh"`
	// self-hosted interactsh server url
	InteractshURL string `yaml:"interactsh-url"`
	// number of requests to keep in the interactions cache
	InteractionsCacheSize int `yaml:"interactions-cache-size"`
	// number of seconds to wait before evicting requests from cache
	InteractionsEviction int `yaml:"interactions-eviction"`
	// number of seconds to wait before each interaction poll request
	InteractionsPollDuration int `yaml:"interactions-poll-duration"`
	// extra time for interaction polling before exiting
	InteractionsCooldownPeriod int `yaml:"interactions-cooldown-period"`
	//  maximum number of requests to send per second
	RateLimit int `yaml:"rate-limit"`
	//  maximum number of requests to send per minute
	RateLimitMinute int `yaml:"rate-limit-minute"`
	//  maximum number of hosts to be analyzed in parallel per template
	BulkSize int `yaml:"bulk-size"`
	//  maximum number of templates to be executed in parallel
	Concurrency int `yaml:"concurrency"`
	// HeadlessBulkSize is the of targets analyzed in parallel for each headless template
	HeadlessBulkSize int `yaml:"headless-bulk-size"`
	// HeadlessTemplateThreads is the number of headless templates executed in parallel
	HeadlessConcurrency int `yaml:"headless-concurrency"`
	//  time to wait in seconds before timeout
	Timeout int `yaml:"timeout"`
	//  number of times to retry a failed request
	Retries int `yaml:"retries"`
	//  max errors for a host before skipping from scan
	HostMaxError int `yaml:"host-max-error"`
	//  stop processing http requests after the first match (may break template/workflow logic)
	StopAtFirstPath bool `yaml:"stop-at-first-path"`
	//  enable templates that require headless browser support
	Headless bool `yaml:"headless"`
	//  seconds to wait for each page in headless mode
	PageTimeout int `yaml:"page-timeout"`
	//  url of the http proxy server
	ProxyURL string `yaml:"proxy-url"`
	//  url of the socks proxy server
	ProxySocksURL string `yaml:"proxy-socks-url"`
}

// DefaultSettings returns the default settings object
func DefaultSettings() *Settings {
	interactOpts := interactsh.NewDefaultOptions(nil, nil, nil)

	return &Settings{
		RateLimit:                  150,
		BulkSize:                   25,
		Concurrency:                25,
		HeadlessBulkSize:           10,
		HeadlessConcurrency:        10,
		Timeout:                    5,
		Retries:                    1,
		HostMaxError:               30,
		InteractshURL:              interactOpts.ServerURL,
		InteractionsCacheSize:      int(interactOpts.CacheSize),
		InteractionsEviction:       int(interactOpts.Eviction.Seconds()),
		InteractionsPollDuration:   int(interactOpts.PollDuration.Seconds()),
		InteractionsCooldownPeriod: int(interactOpts.CooldownPeriod.Seconds()),
	}
}

// todo: add more fields
func (s *Settings) ToTypesOptions() *types.Options {
	return &types.Options{
		RateLimit:                  s.RateLimit,
		BulkSize:                   s.BulkSize,
		TemplateThreads:            s.Concurrency,
		HeadlessBulkSize:           s.HeadlessBulkSize,
		HeadlessTemplateThreads:    s.HeadlessConcurrency,
		Timeout:                    s.Timeout,
		Retries:                    s.Retries,
		MaxHostError:               s.HostMaxError,
		InteractshURL:              s.InteractshURL,
		InteractionsCacheSize:      s.InteractionsCacheSize,
		InteractionsEviction:       s.InteractionsEviction,
		InteractionsPollDuration:   s.InteractionsPollDuration,
		InteractionsCoolDownPeriod: s.InteractionsCooldownPeriod,
	}
}

// InitializeDefaultSettings initializes default settings for the instance
func InitializeDefaultSettings(db *db.Database) error {
	// Also create the queries.
	_, err := db.Queries().GetSettingByName(context.Background(), "default")
	if err == nil {
		return nil // already exists
	}
	var builder strings.Builder
	settings := DefaultSettings()
	if err = yaml.NewEncoder(&builder).Encode(settings); err != nil {
		return err
	}
	err = db.Queries().SetSettings(context.Background(), dbsql.SetSettingsParams{
		Datatype:    "internal",
		Name:        "default",
		Settingdata: builder.String(),
	})
	return err
}
