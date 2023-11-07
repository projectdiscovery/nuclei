package pdcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	uploadEndpoint = "/v1/scans/import"
	dashboardURL   = "https://cloud.projectdiscovery.io/scans/%v"
)

var _ output.Writer = &UploadWriter{}

// UploadWriter is a writer that uploads its output to pdcp
// server to enable web dashboard and more
type UploadWriter struct {
	*output.StandardWriter
	creds     *PDCPCredentials
	tempFile  *os.File
	done      atomic.Bool
	uploadURL *url.URL
}

// NewUploadWriter creates a new upload writer
func NewUploadWriter(creds *PDCPCredentials) (*UploadWriter, error) {
	if creds == nil {
		return nil, fmt.Errorf("no credentials provided")
	}
	u := &UploadWriter{creds: creds}
	// create a temporary file in cache directory
	cacheDir := folderutil.AppCacheDirOrDefault("", config.BinaryName)
	if !fileutil.FolderExists(cacheDir) {
		_ = fileutil.CreateFolder(cacheDir)
	}

	var err error
	// tempfile is created in nuclei-results-<unix-timestamp>.json format
	u.tempFile, err = os.CreateTemp(cacheDir, "nuclei-results-"+strconv.Itoa(int(time.Now().Unix()))+".json")
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create temporary file")
	}
	u.StandardWriter, err = output.NewWriter(
		output.WithWriter(u.tempFile),
		output.WithJson(true, false),
	)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create output writer")
	}
	tmp, err := urlutil.Parse(creds.Server)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not parse server url")
	}
	tmp.Path = uploadEndpoint
	tmp.Update()
	u.uploadURL = tmp.URL
	return u, nil
}

type uploadResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Upload uploads the results to pdcp server
func (u *UploadWriter) Upload() {
	defer u.done.Store(true)

	// start from beginning
	_, _ = u.tempFile.Seek(0, 0)
	scanner := bufio.NewScanner(u.tempFile)
	if scanner.Scan() && scanner.Text() == "" {
		gologger.Verbose().Msgf("Auto Save Skipped, no results found to upload")
		return

	}
	_, _ = u.tempFile.Seek(0, 0)

	id, err := u.upload()
	if err != nil {
		gologger.Error().Msgf("Failed to upload scan result: %v", err)
		gologger.Info().Msgf("you can still manually upload scan results file at %v at cloud.projectdiscovery.io", u.tempFile.Name())
		return
	}
	gologger.Info().Msgf("Successfully uploaded scan result, you can now view results in scans dashboard at %v", fmt.Sprintf(dashboardURL, id))
}

func (u *UploadWriter) upload() (string, error) {
	req, err := retryablehttp.NewRequest(http.MethodPost, u.uploadURL.String(), u.tempFile)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not create upload request")
	}
	req.Header.Set(ApiKeyHeaderName, u.creds.APIKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")

	opts := retryablehttp.DefaultOptionsSingle
	// we are uploading nuclei results which can be large
	// server has a size limit of ~20ish MB
	opts.Timeout = time.Duration(3) * time.Minute
	client := retryablehttp.NewClient(opts)
	resp, err := client.Do(req)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not upload results")
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not get id from response")
	}
	if resp.StatusCode != http.StatusOK {
		return "", errorutil.NewWithErr(err).Msgf("could not upload results got %v", string(bin))
	}
	var uploadResp uploadResponse
	if err := json.Unmarshal(bin, &uploadResp); err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not unmarshal response got %v", string(bin))
	}
	u.removeTempFile()
	return uploadResp.ID, nil
}

// removeTempFile removes the temporary file
func (u *UploadWriter) removeTempFile() {
	_ = os.Remove(u.tempFile.Name())
}

// Close closes the upload writer
func (u *UploadWriter) Close() {
	if !u.done.Load() {
		u.Upload()
	}
}
