package client

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
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
	Page   int
	Size   int
}

// GetIssuesResponse is a response for issues list
type GetIssuesResponse struct {
	Template         string    `json:"template,omitempty"`
	Templateurl      string    `json:"templateUrl,omitempty"`
	Templateid       string    `json:"templateId,omitempty"`
	Templatepath     string    `json:"templatePath,omitempty"`
	Templatename     string    `json:"templateName,omitempty"`
	Author           string    `json:"author,omitempty"`
	Labels           []string  `json:"labels,omitempty"`
	Description      string    `json:"description,omitempty"`
	Reference        []string  `json:"reference,omitempty"`
	Severity         string    `json:"severity,omitempty"`
	Templatemetadata string    `json:"templatemetadata,omitempty"`
	Cvss             float64   `json:"cvss,omitempty"`
	Cwe              []int32   `json:"cwe,omitempty"`
	Cveid            string    `json:"cveid,omitempty"`
	Cvssmetrics      string    `json:"cvssmetrics,omitempty"`
	Remediation      string    `json:"remediation,omitempty"`
	Matchername      string    `json:"matcherName,omitempty"`
	Extractorname    string    `json:"extractorName,omitempty"`
	Resulttype       string    `json:"resultType,omitempty"`
	Host             string    `json:"host,omitempty"`
	Path             string    `json:"path,omitempty"`
	Matchedat        string    `json:"matchedAt,omitempty"`
	Extractedresults []string  `json:"extractedResults,omitempty"`
	Request          string    `json:"request,omitempty"`
	Response         string    `json:"response,omitempty"`
	Metadata         string    `json:"metadata,omitempty"`
	Ip               string    `json:"ip,omitempty"`
	Interaction      string    `json:"interaction,omitempty"`
	Curlcommand      string    `json:"curlCommand,omitempty"`
	Matcherstatus    bool      `json:"matcherStatus,omitempty"`
	Title            string    `json:"title,omitempty"`
	Createdat        time.Time `json:"createdAt,omitempty"`
	Updatedat        time.Time `json:"updatedAt,omitempty"`
	Scansource       string    `json:"scanSource,omitempty"`
	Issuestate       string    `json:"issueState,omitempty"`
	Hash             string    `json:"hash,omitempty"`
	ID               int64     `json:"id,omitempty"`
	Scanid           int64     `json:"scanId,omitempty"`
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
	if req.Page != 0 {
		values.Set("page", strconv.Itoa(req.Page))
	}
	if req.Size != 0 {
		values.Set("size", strconv.Itoa(req.Size))
	}
	if len(values) > 0 {
		parsed.RawQuery = values.Encode()
	}

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	httpreq.Header.Set(HeaderAuthKey, c.token)

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
	httpreq.Header.Set(HeaderAuthKey, c.token)

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
	httpreq.Header.Set(HeaderAuthKey, c.token)

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
	httpreq.Header.Set(HeaderAuthKey, c.token)

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
