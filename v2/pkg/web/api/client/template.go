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
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Templates is an interface implemented by templates service
type Templates interface {
	// GetTemplates returns the list of templates
	GetTemplates(GetTemplatesRequest) ([]GetTemplatesResponse, error)
	// AddTemplate adds a template to the list of templates
	AddTemplate(AddTemplateRequest) (int64, error)
	// UpdateTemplates updates a template contents
	UpdateTemplate(UpdateTemplateRequest) error
	// DeleteTemplate deletes a template from storage
	DeleteTemplate(DeleteTemplateRequest) error
	// GetTemplateRaw returns contents for a template path
	GetTemplateRaw(Path string) (string, error)
	// ExecuteTemplate executes a template with target
	ExecuteTemplate(ExecuteTemplateRequest) (ExecuteTemplateResponse, error)
}

var _ Templates = &TemplatesService{}

// TemplatesService is a service for dealing with templates
type TemplatesService struct {
	*Client
}

// GetTemplatesRequest is a request for /templates list
type GetTemplatesRequest struct {
	Folder string
	Search string
}

// GetTemplatesResponse is a response for /templates list
type GetTemplatesResponse struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Folder    string    `json:"folder"`
	Path      string    `json:"path"`
	Createdat time.Time `json:"createdAt"`
	Updatedat time.Time `json:"updatedAt"`
}

// GetTemplates returns the list of templates for /templates endpoint
func (c *TemplatesService) GetTemplates(req GetTemplatesRequest) ([]GetTemplatesResponse, error) {
	reqURL := fmt.Sprintf("%s/templates", c.baseURL)
	parsed, err := url.Parse(reqURL)
	if err != nil {
		return nil, errors.Wrap(err, "could not get templates")
	}
	values := make(url.Values)
	if req.Folder != "" {
		values.Set("folder", req.Folder)
	}
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
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data []GetTemplatesResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// AddTemplateRequest is a request for template addition
type AddTemplateRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
	Folder   string `json:"folder"`
}

// AddTemplate adds a template to storage
func (c *TemplatesService) AddTemplate(req AddTemplateRequest) (int64, error) {
	reqURL := fmt.Sprintf("%s/templates", c.baseURL)

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
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return 0, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data map[string]int64
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, errors.Wrap(err, "could not json decode response")
	}
	return data["id"], nil
}

// UpdateTemplateRequest is a request for template update
type UpdateTemplateRequest struct {
	Contents string `json:"contents"`
	Path     string `json:"path"`
}

// UpdateTemplate updates a template content by path
func (c *TemplatesService) UpdateTemplate(req UpdateTemplateRequest) error {
	reqURL := fmt.Sprintf("%s/templates", c.baseURL)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodPut, reqURL, &buf)
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

// DeleteTemplateRequest is a request for template deletion
type DeleteTemplateRequest struct {
	Path string `json:"path"`
}

// DeleteTemplate deletes a template from storage
func (c *TemplatesService) DeleteTemplate(req DeleteTemplateRequest) error {
	reqURL := fmt.Sprintf("%s/templates", c.baseURL)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodDelete, reqURL, &buf)
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

// GetTemplateRaw returns raw content for a template
func (c *TemplatesService) GetTemplateRaw(Path string) (string, error) {
	reqURL := fmt.Sprintf("%s/templates/raw?path=%s", c.baseURL, Path)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return "", errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "could not read http request body")
	}
	return string(data), nil
}

// ExecuteTemplateRequest is a request for template execution
type ExecuteTemplateRequest struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// ExecuteTemplateResponse is a response for template execution
type ExecuteTemplateResponse struct {
	Output []*output.ResultEvent `json:"output,omitempty"`
	Debug  map[string]string     `json:"debug"` // Contains debug request response kv pairs
}

// ExecuteTemplate executes a template on target and returns response
func (c *TemplatesService) ExecuteTemplate(req ExecuteTemplateRequest) (ExecuteTemplateResponse, error) {
	reqURL := fmt.Sprintf("%s/templates/execute", c.baseURL)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodPost, reqURL, &buf)
	if err != nil {
		return ExecuteTemplateResponse{}, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return ExecuteTemplateResponse{}, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return ExecuteTemplateResponse{}, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var data ExecuteTemplateResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ExecuteTemplateResponse{}, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}
