package client

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Targets is an interface implemented by targets service
type Targets interface {
	// GetTargets returns the list of targets
	GetTargets(GetTargetsRequest) ([]GetTargetsResponse, error)
	// AddTarget adds a target to the list of targets
	AddTarget(AddTargetRequest) (int64, error)
	// UpdateTarget updates a target contents
	UpdateTarget(UpdateTargetRequest) error
	// DeleteTarget deletes a target from storage
	DeleteTarget(ID int64) error
	// GetTemplateRaw returns contents for a template path
	GetTargetContents(ID int64) (io.ReadCloser, error)
}

var _ Targets = &TargetsService{}

// TargetsService is a service for dealing with targets
type TargetsService struct {
	*Client
}

// GetTargetsRequest is a request for targets list
type GetTargetsRequest struct {
	Search string
}

// GetTargetsResponse is a response for targets list
type GetTargetsResponse struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	InternalID string    `json:"internalId"`
	Filename   string    `json:"filename"`
	Total      int64     `json:"total"`
	Createdat  time.Time `json:"createdAt"`
	Updatedat  time.Time `json:"updatedAt"`
}

// GetTemplates returns the list of templates for /templates endpoint
func (c *TargetsService) GetTargets(req GetTargetsRequest) ([]GetTargetsResponse, error) {
	reqURL := fmt.Sprintf("%s/targets", c.baseURL)

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
	var data []GetTargetsResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// AddTargetRequest is a request for target addition
type AddTargetRequest struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Contents io.Reader
}

// AddTarget adds a target to storage
func (c *TargetsService) AddTarget(req AddTargetRequest) (int64, error) {
	reqURL := fmt.Sprintf("%s/targets", c.baseURL)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("path", req.Path)
	writer.WriteField("name", req.Name)
	fileWriter, err := writer.CreateFormFile("contents", "contents.txt")
	if err != nil {
		return 0, errors.Wrap(err, "could not create form file")
	}
	_, _ = io.Copy(fileWriter, req.Contents)
	writer.Close()

	httpreq, err := retryablehttp.NewRequest(http.MethodPost, reqURL, &buf)
	if err != nil {
		return 0, errors.Wrap(err, "could not make http request")
	}
	httpreq.Header.Set("Content-Type", writer.FormDataContentType())
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

// UpdateTargetRequest is a request for target update
type UpdateTargetRequest struct {
	ID       int64
	TargetID string
	Contents io.Reader
}

// UpdateTemplate updates a target content by path
func (c *TargetsService) UpdateTarget(req UpdateTargetRequest) error {
	reqURL := fmt.Sprintf("%s/targets/%d", c.baseURL, req.ID)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("id", req.TargetID)
	fileWriter, err := writer.CreateFormFile("contents", "contents.txt")
	if err != nil {
		return errors.Wrap(err, "could not create form file")
	}
	_, _ = io.Copy(fileWriter, req.Contents)
	writer.Close()

	httpreq, err := retryablehttp.NewRequest(http.MethodPost, reqURL, &buf)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}
	httpreq.Header.Set("Content-Type", writer.FormDataContentType())

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

// DeleteTemplate deletes a template from storage
func (c *TargetsService) DeleteTarget(ID int64) error {
	reqURL := fmt.Sprintf("%s/targets/%d", c.baseURL, ID)

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

// GetTargetContents returns contents for a target
func (c *TargetsService) GetTargetContents(ID int64) (io.ReadCloser, error) {
	reqURL := fmt.Sprintf("%s/targets/%d", c.baseURL, ID)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
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
	return resp.Body, nil
}
