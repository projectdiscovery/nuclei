package nucleicloud

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Client is a client for result retrieval from nuclei-cloud API
type Client struct {
	baseURL    string
	apiKey     string
	httpclient *retryablehttp.Client
}

const (
	pollInterval   = 1 * time.Second
	defaultBaseURL = "http://webapp.localhost"
)

// New returns a nuclei-cloud API client
func New(baseURL, apiKey string) *Client {
	options := retryablehttp.DefaultOptionsSingle
	options.Timeout = 15 * time.Second
	client := retryablehttp.NewClient(options)

	baseAppURL := baseURL
	if baseAppURL == "" {
		baseAppURL = defaultBaseURL
	}
	return &Client{httpclient: client, baseURL: baseAppURL, apiKey: apiKey}
}

// AddScan adds a scan for templates and target to nuclei server
func (c *Client) AddScan(req *AddScanRequest) (string, error) {
	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(req); err != nil {
		return "", errors.Wrap(err, "could not json encode scan request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/scan", c.baseURL), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return "", errors.Wrap(err, "could not make request")
	}
	httpReq.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpclient.Do(httpReq)
	if err != nil {
		return "", errors.Wrap(err, "could not do request")
	}
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return "", errors.Errorf("could not do request %d: %s", resp.StatusCode, string(data))
	}
	var data map[string]string
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		resp.Body.Close()
		return "", errors.Wrap(err, "could not decode resp")
	}
	resp.Body.Close()
	id := data["id"]
	return id, nil
}

// GetResults gets results from nuclei server for an ID
// until there are no more results left to retrieve.
func (c *Client) GetResults(ID string, callback func(*output.ResultEvent)) error {
	lastID := int64(0)
	for {
		httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/results?id=%s&from=%d", c.baseURL, ID, lastID), nil)
		if err != nil {
			return errors.Wrap(err, "could not make request")
		}
		httpReq.Header.Set("X-API-Key", c.apiKey)

		resp, err := c.httpclient.Do(httpReq)
		if err != nil {
			return errors.Wrap(err, "could not do request")
		}
		if resp.StatusCode != 200 {
			data, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			return errors.Errorf("could not do request %d: %s", resp.StatusCode, string(data))
		}
		var items GetResultsResponse
		if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
			resp.Body.Close()
			return errors.Wrap(err, "could not decode results")
		}
		resp.Body.Close()

		for _, item := range items.Items {
			lastID = item.ID

			var result output.ResultEvent
			if err := jsoniter.NewDecoder(strings.NewReader(item.Raw)).Decode(&result); err != nil {
				return errors.Wrap(err, "could not decode result item")
			}
			callback(&result)
		}
		if items.Finished {
			break
		}
		time.Sleep(pollInterval)
	}
	return nil
}
