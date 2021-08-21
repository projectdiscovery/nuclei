package es

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	b64 "encoding/base64"
	"encoding/json"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

// Options contains necessary options required for elasticsearch communicaiton
type Options struct {
	// Full url for elasticsearch
	ESIP string
	// Full url for elasticsearch
	ESPort int
	// Enable/Disable SSL
	ESSSL bool
	// Enable/DIsable SSL verificaiton
	ESSSLVerificaiton bool
	// Elasticsearch username
	ESUsername string
	// Elasticsearch password
	ESPassword string
}

type data struct {
	Event     *output.ResultEvent `json:"event"`
	Timestamp string              `json:"@timestamp"`
}

// Exporter type for elasticsearch
type Exporter struct {
	elasticsearch *http.Client
	req           *http.Request
	wg            *sync.Mutex
}

// New creates and returns a new exporter for elasticsearch
func New(option *Options) (*Exporter, error) {

	var ei *Exporter

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: option.ESSSLVerificaiton},
	}
	c := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	// preparing url for elasticsearch
	url := `http://`
	if option.ESSSL {
		url = `https://`
	}
	url = fmt.Sprintf(url+"%s:%d/nuclei-export/_doc", option.ESIP, option.ESPort)

	// creafting a request
	req2, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return ei, nil
	}

	// if authentication is required
	if len(option.ESUsername) != 0 && len(option.ESPassword) != 0 {
		auth := b64.StdEncoding.EncodeToString([]byte(option.ESUsername + ":" + option.ESPassword))
		auth = "Basic " + auth
		req2.Header.Add("Authorization", auth)
	}
	req2.Header.Add("Content-Type", "application/json")

	ei = &Exporter{
		elasticsearch: c,
		req:           req2,
		wg:            &sync.Mutex{},
	}

	return ei, nil
}

// Export exports a passed result event to disk
func (i *Exporter) Export(event *output.ResultEvent) error {
	i.wg.Lock()
	defer i.wg.Unlock()
	defer func() { i.req.Body = nil }()

	d := data{
		Event:     event,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	b, err := json.Marshal(&d)
	if err != nil {
		return err
	}
	i.req.Body = io.NopCloser(strings.NewReader(string(b)))

	res, err := i.elasticsearch.Do(i.req)
	b, _ = io.ReadAll(res.Body)
	if err != nil {
		return errors.New(err.Error() + "error thrown by elasticsearch " + string(b))
	}

	if res.StatusCode >= 300 {
		return errors.New("elasticsearch responded with an error: " + string(b))
	}

	return nil
}

// Close closes the exporter after operation
func (i *Exporter) Close() error {
	return nil
}
