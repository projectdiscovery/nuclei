package client

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Settings is an interface implemented by settings service
type Settings interface {
	// GetSettings returns the list of settings
	GetSettings() ([]GetSettingsResponse, error)
	// AddSetting adds a setting to the list of settings
	AddSetting(AddSettingRequest) error
	// UpdateSetting updates a setting contents
	UpdateSetting(UpdateSettingRequest) error
	// GetSetting returns setting content for a name
	GetSetting(Name string) (GetSettingsResponse, error)
}

var _ Settings = &SettingsService{}

// SettingsService is a service for dealing with settings
type SettingsService struct {
	*Client
}

// GetSettingsResponse is a response for get settings request
type GetSettingsResponse struct {
	Name     string `json:"name"`
	Contents string `json:"contents"`
	Type     string `json:"type"`
}

// GetSettings returns the list of settings
func (c *SettingsService) GetSettings() ([]GetSettingsResponse, error) {
	reqURL := fmt.Sprintf("%s/settings", c.baseURL)

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
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	var data []GetSettingsResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not json decode response")
	}
	return data, nil
}

// AddSettingRequest is a request for setting addition
type AddSettingRequest struct {
	Name     string `json:"name"`
	Contents string `json:"contents"`
	Type     string `json:"type"`
}

// AddSetting adds a setting to the list of settings
func (c *SettingsService) AddSetting(req AddSettingRequest) error {
	reqURL := fmt.Sprintf("%s/settings", c.baseURL)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodPost, reqURL, &buf)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return errors.Wrap(err, "could not make http request")
	}
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return nil
}

// UpdateTargetRequest is a request for setting update
type UpdateSettingRequest struct {
	Name     string `json:"-"`
	Contents string `json:"contents"`
	Type     string `json:"type"`
}

// UpdateTemplate updates a target content by path
func (c *SettingsService) UpdateSetting(req UpdateSettingRequest) error {
	reqURL := fmt.Sprintf("%s/settings/%s", c.baseURL, req.Name)

	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(req)

	httpreq, err := retryablehttp.NewRequest(http.MethodPost, reqURL, &buf)
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

// DeleteTemplate deletes a template from storage
func (c *SettingsService) GetSetting(Name string) (GetSettingsResponse, error) {
	reqURL := fmt.Sprintf("%s/settings/%s", c.baseURL, Name)

	httpreq, err := retryablehttp.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return GetSettingsResponse{}, errors.Wrap(err, "could not make http request")
	}
	httpreq.SetBasicAuth(c.username, c.password)

	resp, err := c.httpclient.Do(httpreq)
	if err != nil {
		return GetSettingsResponse{}, errors.Wrap(err, "could not make http request")
	}
	defer func() {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return GetSettingsResponse{}, fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(data))
	}
	var body GetSettingsResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&body); err != nil {
		return GetSettingsResponse{}, errors.Wrap(err, "could not decode json response")
	}
	return body, nil
}
