package splunk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/useragent"
)

// Options contains necessary options required for splunk communication
type Options struct {
	// Host is the hostname and port of the splunk instance
	Host string `yaml:"host" validate:"required"`
	Port int    `yaml:"port" validate:"gte=0,lte=65535"`
	// SSL (optional) enables ssl for splunk connection
	SSL bool `yaml:"ssl"`
	// SSLVerification (optional) disables SSL verification for splunk
	SSLVerification bool `yaml:"ssl-verification"`
	// Token for HEC instance
	Token     string `yaml:"token"  validate:"required"`
	IndexName string `yaml:"index-name"  validate:"required"`

	HttpClient *retryablehttp.Client `yaml:"-"`
}

type data struct {
	Event *output.ResultEvent `json:"event"`
}

// Exporter type for splunk
type Exporter struct {
	url            string
	authentication string
	splunk         *http.Client
}

// New creates and returns a new exporter for splunk
func New(option *Options) (*Exporter, error) {
	var ei *Exporter

	// we do not allow nil http client
	if option.HttpClient == nil {
		return nil, errors.New("http client is nil")
	}

	// preparing url for splunk
	scheme := "http://"
	if option.SSL {
		scheme = "https://"
	}

	// Authentication header for HEC
	authentication := "Splunk " + option.Token

	// add HEC endpoint, index, source, sourcetype
	addr := option.Host
	if option.Port > 0 {
		addr = net.JoinHostPort(addr, fmt.Sprint(option.Port))
	}
	base_url := fmt.Sprintf("%s%s", scheme, addr)
	sourcetype := "nuclei:splunk-hec:exporter:json"
	url := fmt.Sprintf("%s/services/collector/event?index=%s&sourcetype=%s&source=%s", base_url, option.IndexName, sourcetype, base_url)

	ei = &Exporter{
		url:            url,
		authentication: authentication,
		splunk:         option.HttpClient.HTTPClient,
	}
	return ei, nil
}

// Export exports a passed result event to Splunk
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	// creating a request
	req, err := http.NewRequest(http.MethodPost, exporter.url, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	if len(exporter.authentication) > 0 {
		req.Header.Add("Authorization", exporter.authentication)
	}
	userAgent := useragent.PickRandom()
	req.Header.Set("User-Agent", userAgent.Raw)
	req.Header.Add("Content-Type", "application/json")

	d := data{Event: event}
	b, err := json.Marshal(&d)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(b))

	res, err := exporter.splunk.Do(req)
	if err != nil {
		return err
	}

	b, err = io.ReadAll(res.Body)
	if err != nil {
		return errors.New(err.Error() + "error thrown by splunk " + string(b))
	}
	if res.StatusCode >= http.StatusMultipleChoices {
		return errors.New("splunk responded with an error: " + string(b))
	}
	return nil
}

// Close closes the exporter after operation
func (exporter *Exporter) Close() error {
	return nil
}
