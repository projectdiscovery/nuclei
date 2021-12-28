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

// Scans is an interface implemented by scans service
type Scans interface {
	// GetScans returns the list of scans
	GetScans(GetScansRequest) ([]GetScansResponse, error)
	// AddScan adds a scan to the list of scans
	AddScan(AddScanRequest) (int64, error)
	// GetScanProgress returns the ongoing scan progress
	GetScanProgress() (map[int64]float64, error)
	// UpdateScan updates a scan state
	UpdateScan(ID int64, req UpdateScanRequest) error
	// DeleteScan deletes a scan
	DeleteScan(ID int64) error
	// GetScan returns a scan from the db
	GetScan(ID int64) (GetScansResponse, error)
	// ExecuteScan executes a scan
	ExecuteScan(ID int64) error
	// GetScanMatches returns matches for a scan
	GetScanMatches(ID int64) ([]GetScanMatchesResponse, error)
	// GetScanErrors returns errors for a scan
	GetScanErrors(ID int64) ([]GetScanErrorsResponse, error)
}

var _ Scans = &ScansService{}

// ScansService is a service for dealing with scans
type ScansService struct {
	*Client
}

// GetScansRequest is a request for scans list
type GetScansRequest struct {
	Search string
}

// GetScansResponse is a response for scans list
type GetScansResponse struct {
	ID                int64         `json:"id,omitempty"`
	Status            string        `json:"status,omitempty"`
	Name              string        `json:"name,omitempty"`
	Templates         []string      `json:"templates,omitempty"`
	Targets           []string      `json:"targets,omitempty"`
	Config            string        `json:"config,omitempty"` // nuclei config, default -> "default"
	RunNow            bool          `json:"runNow,omitempty"`
	Reporting         string        `json:"reportingConfig,omitempty"`
	ScheduleOccurence string        `json:"scheduleOccurence,omitempty"`
	ScheduleTime      string        `json:"scheduleTime,omitempty"`
	ScanSource        string        `json:"scanSource,omitempty"`
	ScanTime          time.Duration `json:"scanTime,omitempty"`
	Hosts             int64         `json:"hosts,omitempty"`
}

// GetScans returns the list of scans
func (c *ScansService) GetScans(req GetScansRequest) ([]GetScansResponse, error) {
	reqURL := fmt.Sprintf("%s/scans", c.baseURL)

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
	var data []GetScansResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// AddScanRequest is a request for scans addition
type AddScanRequest struct {
	Name              string   `json:"name"`
	Templates         []string `json:"templates"`
	Targets           []string `json:"targets"`
	Config            string   `json:"config"` // nuclei config, default -> "default"
	RunNow            bool     `json:"runNow"`
	Reporting         string   `json:"reportingConfig"`
	ScheduleOccurence string   `json:"scheduleOccurence"`
	ScheduleTime      string   `json:"scheduleTime"`
	ScanSource        string   `json:"scanSource"`
}

// AddScan adds a scan to storage
func (c *ScansService) AddScan(req AddScanRequest) (int64, error) {
	reqURL := fmt.Sprintf("%s/scans", c.baseURL)

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

// UpdateScanRequest is a request for scans update
type UpdateScanRequest struct {
	Stop bool `json:"stop"`
}

// UpdateScan updates a scan state
func (c *ScansService) UpdateScan(ID int64, req UpdateScanRequest) error {
	reqURL := fmt.Sprintf("%s/scans/%d", c.baseURL, ID)

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

// DeleteScan deletes a scan from storage
func (c *ScansService) DeleteScan(ID int64) error {
	reqURL := fmt.Sprintf("%s/scans/%d", c.baseURL, ID)

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

// GetScanProgress returns running scans progress
func (c *ScansService) GetScanProgress() (map[int64]float64, error) {
	reqURL := fmt.Sprintf("%s/scans/progress", c.baseURL)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data map[int64]float64
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// GetScan returns a scan from database
func (c *ScansService) GetScan(ID int64) (GetScansResponse, error) {
	reqURL := fmt.Sprintf("%s/scans/%d", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return GetScansResponse{}, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return GetScansResponse{}, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return GetScansResponse{}, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data GetScansResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return GetScansResponse{}, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// ExecuteScan executes a scan from database
func (c *ScansService) ExecuteScan(ID int64) error {
	reqURL := fmt.Sprintf("%s/scans/%d/execute", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
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

// GetScanMatchesResponse is a response for get matches endpoint
type GetScanMatchesResponse struct {
	TemplateName string `json:"templateName,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Author       string `json:"author,omitempty"`
	MatchedAt    string `json:"matchedAt,omitempty"`
}

// GetScanMatches returns scan matches from server
func (c *ScansService) GetScanMatches(ID int64) ([]GetScanMatchesResponse, error) {
	reqURL := fmt.Sprintf("%s/scans/%d/matches", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data []GetScanMatchesResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// GetScanErrorsResponse is a response for scan errors
type GetScanErrorsResponse struct {
	ID int64
}

// GetScanErrors returns errors for scan
func (c *ScansService) GetScanErrors(ID int64) ([]GetScanErrorsResponse, error) {
	reqURL := fmt.Sprintf("%s/scans/%d/errors", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return nil, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data []GetScanErrorsResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}
