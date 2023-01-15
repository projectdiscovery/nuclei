package nucleicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	pollInterval   = 3 * time.Second
	resultSize     = 100
	defaultBaseURL = "https://cloud-dev.nuclei.sh"
)

// HTTPErrorRetryPolicy is to retry for HTTPCodes >= 500.
func HTTPErrorRetryPolicy() func(ctx context.Context, resp *http.Response, err error) (bool, error) {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if resp != nil && resp.StatusCode >= http.StatusInternalServerError {
			return true, errors.New(resp.Status)
		}
		return retryablehttp.CheckRecoverableErrors(ctx, resp, err)
	}
}

// New returns a nuclei-cloud API client
func New(baseURL, apiKey string) *Client {
	options := retryablehttp.DefaultOptionsSingle
	options.NoAdjustTimeout = true
	options.Timeout = 60 * time.Second
	options.CheckRetry = HTTPErrorRetryPolicy()
	client := retryablehttp.NewClient(options)

	baseAppURL := baseURL
	if baseAppURL == "" {
		baseAppURL = defaultBaseURL
	}
	return &Client{httpclient: client, baseURL: baseAppURL, apiKey: apiKey}
}

// AddScan adds a scan for templates and target to nuclei server
func (c *Client) AddScan(req *AddScanRequest) (int64, error) {
	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(req); err != nil {
		return 0, errors.Wrap(err, "could not encode request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/scan", c.baseURL), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return 0, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return 0, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	var data map[string]int64
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, errors.Wrap(err, "could not decode resp")
	}
	id := data["id"]
	return id, nil
}

// GetResults gets results from nuclei server for an ID
// until there are no more results left to retrieve.
func (c *Client) GetResults(ID int64, checkProgress bool, limit int, callback func(*output.ResultEvent)) error {
	lastID := int64(0)

	for {
		uri := fmt.Sprintf("%s/results?id=%d&from=%d&size=%d", c.baseURL, ID, lastID, limit)
		httpReq, err := retryablehttp.NewRequest(http.MethodGet, uri, nil)
		if err != nil {
			return errors.Wrap(err, "could not make request")
		}

		resp, err := c.sendRequest(httpReq)
		if err != nil {
			return errors.Wrap(err, "could not do request")
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

		// This is checked during scan is added else if no item found break out of loop.
		if checkProgress {
			if items.Finished && len(items.Items) == 0 {
				break
			}
		} else if len(items.Items) == 0 {
			break
		}

		time.Sleep(pollInterval)
	}
	return nil
}

func (c *Client) GetScans(limit int, from string) ([]GetScanRequest, error) {
	var items []GetScanRequest
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/scan?from=%s&size=%d", c.baseURL, url.QueryEscape(from), limit), nil)
	if err != nil {
		return items, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
		return items, errors.Wrap(err, "could not decode results")
	}
	return items, nil
}

func (c *Client) GetScan(id int64) (GetScanRequest, error) {
	var items GetScanRequest
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/scan/%d", c.baseURL, id), nil)
	if err != nil {
		return items, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return items, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
		return items, errors.Wrap(err, "could not decode results")
	}
	return items, nil
}

// Delete a scan and it's issues by the scan id.
func (c *Client) DeleteScan(id int64) (DeleteScanResults, error) {
	deletescan := DeleteScanResults{}
	httpReq, err := retryablehttp.NewRequest(http.MethodDelete, fmt.Sprintf("%s/scan?id=%d", c.baseURL, id), nil)
	if err != nil {
		return deletescan, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return deletescan, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&deletescan); err != nil {
		return deletescan, errors.Wrap(err, "could not delete scan")
	}
	return deletescan, nil
}

// StatusDataSource returns the status for a data source
func (c *Client) StatusDataSource(statusRequest StatusDataSourceRequest) (int64, error) {
	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(statusRequest); err != nil {
		return 0, errors.Wrap(err, "could not encode request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/datasources/status", c.baseURL), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return 0, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return 0, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	var data StatusDataSourceResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, errors.Wrap(err, "could not decode resp")
	}
	return data.ID, nil
}

// AddDataSource adds a new data source
func (c *Client) AddDataSource(req AddDataSourceRequest) (*AddDataSourceResponse, error) {
	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(req); err != nil {
		return nil, errors.Wrap(err, "could not encode request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/datasources", c.baseURL), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, errors.Wrap(err, "could not make request")
	}
	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	var data AddDataSourceResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not decode resp")
	}
	return &data, nil
}

// SyncDataSource syncs contents for a data source. The call blocks until
// update is completed.
func (c *Client) SyncDataSource(ID int64) error {
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/datasources/%d/sync", c.baseURL, ID), nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// ExistsDataSourceItem identifies whether data source item exist
func (c *Client) ExistsDataSourceItem(req ExistsDataSourceItemRequest) error {
	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(req); err != nil {
		return errors.Wrap(err, "could not encode request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/datasources/exists", c.baseURL), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) ListDatasources() ([]GetDataSourceResponse, error) {
	var items []GetDataSourceResponse
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/datasources", c.baseURL), nil)
	if err != nil {
		return items, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
		return items, errors.Wrap(err, "could not decode results")
	}
	return items, nil
}

func (c *Client) ListReportingSources() ([]GetReportingSourceResponse, error) {
	var items []GetReportingSourceResponse
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/reporting", c.baseURL), nil)
	if err != nil {
		return items, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
		return items, errors.Wrap(err, "could not decode results")
	}
	return items, nil
}

func (c *Client) ToggleReportingSource(ID int64, status bool) error {
	r := ReportingSourceStatus{Enabled: status}

	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(r); err != nil {
		return errors.Wrap(err, "could not encode request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPut, fmt.Sprintf("%s/reporting/%d", c.baseURL, ID), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) ListTargets(query string) ([]GetTargetResponse, error) {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/targets")
	if query != "" {
		_, _ = builder.WriteString("?query=")
		_, _ = builder.WriteString(url.QueryEscape(query))
	}

	var items []GetTargetResponse
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, builder.String(), nil)
	if err != nil {
		return items, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
		return items, errors.Wrap(err, "could not decode results")
	}
	return items, nil
}

func (c *Client) ListTemplates(query string) ([]GetTemplatesResponse, error) {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/templates")
	if query != "" {
		_, _ = builder.WriteString("?query=")
		_, _ = builder.WriteString(url.QueryEscape(query))
	}

	var items []GetTemplatesResponse
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, builder.String(), nil)
	if err != nil {
		return items, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&items); err != nil {
		return items, errors.Wrap(err, "could not decode results")
	}
	return items, nil
}

func (c *Client) RemoveDatasource(datasource int64, name string) error {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/datasources")

	if name != "" {
		_, _ = builder.WriteString("?name=")
		_, _ = builder.WriteString(name)
	} else if datasource != 0 {
		_, _ = builder.WriteString("?id=")
		_, _ = builder.WriteString(strconv.FormatInt(datasource, 10))
	}

	httpReq, err := retryablehttp.NewRequest(http.MethodDelete, builder.String(), nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) AddTemplate(name, contents string) (string, error) {
	file, err := os.Open(contents)
	if err != nil {
		return "", errors.Wrap(err, "could not open contents")
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("name", name)
	fileWriter, _ := writer.CreateFormFile("file", filepath.Base(contents))
	_, _ = io.Copy(fileWriter, file)
	_ = writer.Close()

	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/templates", c.baseURL), &buf)
	if err != nil {
		return "", errors.Wrap(err, "could not make request")
	}
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return "", errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	var item AddItemResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&item); err != nil {
		return "", errors.Wrap(err, "could not decode results")
	}
	return item.Ok, nil
}

func (c *Client) AddTarget(name, contents string) (string, error) {
	file, err := os.Open(contents)
	if err != nil {
		return "", errors.Wrap(err, "could not open contents")
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("name", name)
	fileWriter, _ := writer.CreateFormFile("file", filepath.Base(contents))
	_, _ = io.Copy(fileWriter, file)
	_ = writer.Close()

	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/targets", c.baseURL), &buf)
	if err != nil {
		return "", errors.Wrap(err, "could not make request")
	}
	httpReq.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return "", errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	var item AddItemResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&item); err != nil {
		return "", errors.Wrap(err, "could not decode results")
	}
	return item.Ok, nil
}

func (c *Client) RemoveTemplate(ID int64, name string) error {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/templates")

	if name != "" {
		_, _ = builder.WriteString("?name=")
		_, _ = builder.WriteString(name)
	} else if ID != 0 {
		_, _ = builder.WriteString("?id=")
		_, _ = builder.WriteString(strconv.FormatInt(ID, 10))
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodDelete, builder.String(), nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) RemoveTarget(ID int64, name string) error {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/targets")

	if name != "" {
		_, _ = builder.WriteString("?name=")
		_, _ = builder.WriteString(name)
	} else if ID != 0 {
		_, _ = builder.WriteString("?id=")
		_, _ = builder.WriteString(strconv.FormatInt(ID, 10))
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodDelete, builder.String(), nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) GetTarget(ID int64, name string) (io.ReadCloser, error) {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/targets/get")

	if name != "" {
		_, _ = builder.WriteString("?name=")
		_, _ = builder.WriteString(name)
	} else if ID != 0 {
		_, _ = builder.WriteString("?id=")
		_, _ = builder.WriteString(strconv.FormatInt(ID, 10))
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, builder.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	return resp.Body, nil
}

func (c *Client) GetTemplate(ID int64, name string) (io.ReadCloser, error) {
	var builder strings.Builder
	_, _ = builder.WriteString(c.baseURL)
	_, _ = builder.WriteString("/templates/get")

	if name != "" {
		_, _ = builder.WriteString("?name=")
		_, _ = builder.WriteString(name)
	} else if ID != 0 {
		_, _ = builder.WriteString("?id=")
		_, _ = builder.WriteString(strconv.FormatInt(ID, 10))
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, builder.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	return resp.Body, nil
}

func (c *Client) ExistsTarget(id int64) (ExistsInputResponse, error) {
	var item ExistsInputResponse
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/targets/%d/exists", c.baseURL, id), nil)
	if err != nil {
		return item, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return item, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&item); err != nil {
		return item, errors.Wrap(err, "could not decode results")
	}
	return item, nil
}

func (c *Client) ExistsTemplate(id int64) (ExistsInputResponse, error) {
	var item ExistsInputResponse
	httpReq, err := retryablehttp.NewRequest(http.MethodGet, fmt.Sprintf("%s/templates/%d/exists", c.baseURL, id), nil)
	if err != nil {
		return item, errors.Wrap(err, "could not make request")
	}

	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return item, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	if err := jsoniter.NewDecoder(resp.Body).Decode(&item); err != nil {
		return item, errors.Wrap(err, "could not decode results")
	}
	return item, nil
}

const apiKeyParameter = "X-API-Key"

type errorResponse struct {
	Message string `json:"message"`
}

func (c *Client) sendRequest(req *retryablehttp.Request) (*http.Response, error) {
	req.Header.Set(apiKeyParameter, c.apiKey)

	resp, err := c.httpclient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var errRes errorResponse
		if err = json.NewDecoder(bytes.NewReader(data)).Decode(&errRes); err == nil {
			return nil, errors.New(errRes.Message)
		}
		return nil, fmt.Errorf("unknown error, status code: %d=%s", resp.StatusCode, string(data))
	}
	return resp, nil
}

// AddReportingSource adds a new data source
func (c *Client) AddReportingSource(req AddReportingSourceRequest) (*AddReportingSourceResponse, error) {
	var buf bytes.Buffer
	if err := jsoniter.NewEncoder(&buf).Encode(req); err != nil {
		return nil, errors.Wrap(err, "could not encode request")
	}
	httpReq, err := retryablehttp.NewRequest(http.MethodPost, fmt.Sprintf("%s/reporting/add-source", c.baseURL), bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, errors.Wrap(err, "could not make request")
	}
	resp, err := c.sendRequest(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	var data AddReportingSourceResponse
	if err := jsoniter.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, errors.Wrap(err, "could not decode resp")
	}
	return &data, nil
}
