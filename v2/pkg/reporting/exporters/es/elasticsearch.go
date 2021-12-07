package es

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
)

// Options contains necessary options required for elasticsearch communication
type Options struct {
	// IP for elasticsearch instance
	IP string `yaml:"ip"  validate:"required,ip"`
	// Port is the port of elasticsearch instance
	Port int `yaml:"port"  validate:"required,gte=0,lte=65535"`
	// SSL (optional) enables ssl for elasticsearch connection
	SSL bool `yaml:"ssl"`
	// SSLVerification (optional) disables SSL verification for elasticsearch
	SSLVerification bool `yaml:"ssl-verification"`
	// Username for the elasticsearch instance
	Username string `yaml:"username"  validate:"required"`
	// Password is the password for elasticsearch instance
	Password string `yaml:"password"  validate:"required"`
	// IndexName is the name of the elasticsearch index
	IndexName string `yaml:"index-name"  validate:"required"`
}

type data struct {
	Event     *output.ResultEvent `json:"event"`
	Timestamp string              `json:"@timestamp"`
}

// Exporter type for elasticsearch
type Exporter struct {
	url            string
	authentication string
	elasticsearch  *http.Client
}

// New creates and returns a new exporter for elasticsearch
func New(option *Options) (*Exporter, error) {
	var ei *Exporter

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			DialContext:         protocolstate.Dialer.Dial,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: option.SSLVerification},
		},
	}
	// preparing url for elasticsearch
	scheme := "http://"
	if option.SSL {
		scheme = "https://"
	}
	// if authentication is required
	var authentication string
	if len(option.Username) > 0 && len(option.Password) > 0 {
		auth := base64.StdEncoding.EncodeToString([]byte(option.Username + ":" + option.Password))
		auth = "Basic " + auth
		authentication = auth
	}
	url := fmt.Sprintf("%s%s:%d/%s/_doc", scheme, option.IP, option.Port, option.IndexName)

	ei = &Exporter{
		url:            url,
		authentication: authentication,
		elasticsearch:  client,
	}
	return ei, nil
}

// Export exports a passed result event to elasticsearch
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	// creating a request
	req, err := http.NewRequest(http.MethodPost, exporter.url, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	if len(exporter.authentication) > 0 {
		req.Header.Add("Authorization", exporter.authentication)
	}
	req.Header.Add("Content-Type", "application/json")

	d := data{
		Event:     event,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	b, err := json.Marshal(&d)
	if err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(b))

	res, err := exporter.elasticsearch.Do(req)
	if err != nil {
		return err
	}

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.New(err.Error() + "error thrown by elasticsearch " + string(b))
	}

	if res.StatusCode >= 300 {
		return errors.New("elasticsearch responded with an error: " + string(b))
	}
	return nil
}

// Close closes the exporter after operation
func (exporter *Exporter) Close() error {
	return nil
}
