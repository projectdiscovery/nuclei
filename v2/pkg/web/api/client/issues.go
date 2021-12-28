package client

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Issues is an interface implemented by issues service
type Issues interface {
	// GetIssues returns the list of issues
	GetIssues(GetIssuesRequest) ([]GetIssuesResponse, error)
	// AddIssue adds a issue to the list of issues
	AddIssue(AddIssueRequest) (int64, error)
	// GetScan returns a issue from the db
	GetIssue(ID int64) (GetIssuesResponse, error)
	// UpdateIssue updates a issue state
	UpdateIssue(ID int64, req UpdateIssueRequest) error
	// DeleteIssue deletes a issue
	DeleteIssue(ID int64) error
}

var _ Issues = &IssuesService{}

// IssuesService is a service for dealing with issues
type IssuesService struct {
	*Client
}

// GetIssuesRequest is a request for issues list
type GetIssuesRequest struct {
	Search string
}

// GetIssuesResponse is a response for issues list
type GetIssuesResponse struct {
	ID            int64     `json:"id,omitempty"`
	ScanID        int64     `json:"scanId,omitempty"`
	Matchedat     string    `json:"matchedAt,omitempty"`
	Title         string    `json:"title,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Scansource    string    `json:"scanSource,omitempty"`
	Issuestate    string    `json:"issueState,omitempty"`
	Description   string    `json:"description,omitempty"`
	Author        string    `json:"author,omitempty"`
	Cvss          float64   `json:"cvss,omitempty"`
	Cwe           []int32   `json:"cwe,omitempty"`
	Labels        []string  `json:"labels,omitempty"`
	Issuedata     string    `json:"issueData,omitempty"`
	Issuetemplate string    `json:"issueTemplate,omitempty"`
	Templatename  string    `json:"templateName,omitempty"`
	Remediation   string    `json:"remediation,omitempty"`
	Createdat     time.Time `json:"createdAt,omitempty"`
	Updatedat     time.Time `json:"updatedAt,omitempty"`
}

// GetIssues returns the list of scans
func (c *IssuesService) GetIssues(req GetIssuesRequest) ([]GetIssuesResponse, error) {
	reqURL := fmt.Sprintf("%s/issues", c.baseURL)

	parsed, err := url.Parse(reqURL)
	if err != nil {
		return nil, errors.Wrap(err, "could not get templates")
	}
	values := make(url.Values)
	if req.Search != "" {
		values.Set("search", req.Search)
	}
	if len(values) > 0 {
		parsed.RawQuery = values.Encode()
	}

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	var data []GetIssuesResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// AddIssueRequest is a request for issue addition
type AddIssueRequest struct {
	ScanID        int64     `json:"scanId"`
	Matchedat     string    `json:"matchedAt"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Scansource    string    `json:"scanSource"`
	Issuestate    string    `json:"issueState"`
	Description   string    `json:"description"`
	Author        string    `json:"author"`
	Cvss          float64   `json:"cvss"`
	Cwe           []int32   `json:"cwe"`
	Labels        []string  `json:"labels"`
	Issuedata     string    `json:"issueData"`
	Issuetemplate string    `json:"issueTemplate"`
	Templatename  string    `json:"templateName"`
	Remediation   string    `json:"remediation"`
	Createdat     time.Time `json:"createdAt"`
	Updatedat     time.Time `json:"updatedAt"`
}

// AddIssue adds a issue to storage
func (c *IssuesService) AddIssue(req AddIssueRequest) (int64, error) {
	reqURL := fmt.Sprintf("%s/issues", c.baseURL)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodPost, reqURL, &buf)
	if err != nil {
		return 0, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return 0, errors.Wrap(err, "could not make http request")
	}
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return 0, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	var data map[string]int64
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, errors.Wrap(err, "could not json decode response")
	}
	return data["id"], nil
}

// UpdateIssueRequest is a request for issue update
type UpdateIssueRequest struct {
	State string `json:"state"`
}

// UpdataeIssue updates a issue state
func (c *IssuesService) UpdateIssue(ID int64, req UpdateIssueRequest) error {
	reqURL := fmt.Sprintf("%s/issues/%d", c.baseURL, ID)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodPut, reqURL, &buf)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

// DeleteIssue deletes a issue from storage
func (c *IssuesService) DeleteIssue(ID int64) error {
	reqURL := fmt.Sprintf("%s/issues/%d", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

// GetIssue returns a issue from database
func (c *IssuesService) GetIssue(ID int64) (GetIssuesResponse, error) {
	reqURL := fmt.Sprintf("%s/issues/%d", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return GetIssuesResponse{}, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return GetIssuesResponse{}, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return GetIssuesResponse{}, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data GetIssuesResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return GetIssuesResponse{}, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}
