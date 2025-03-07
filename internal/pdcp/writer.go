package pdcp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/retryablehttp-go"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
	unitutils "github.com/projectdiscovery/utils/unit"
	updateutils "github.com/projectdiscovery/utils/update"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	uploadEndpoint = "/v1/scans/import"
	appendEndpoint = "/v1/scans/%s/import"
	flushTimer     = time.Minute
	MaxChunkSize   = 4 * unitutils.Mega // 4 MB
	xidRe          = `^[a-z0-9]{20}$`
	teamIDHeader   = "X-Team-Id"
	NoneTeamID     = "none"
)

var (
	xidRegex               = regexp.MustCompile(xidRe)
	_        output.Writer = &UploadWriter{}
	// teamID if given
	TeamIDEnv = env.GetEnvOrDefault("PDCP_TEAM_ID", NoneTeamID)
)

// UploadWriter is a writer that uploads its output to pdcp
// server to enable web dashboard and more
type UploadWriter struct {
	*output.StandardWriter
	creds     *pdcpauth.PDCPCredentials
	uploadURL *url.URL
	client    *retryablehttp.Client
	cancel    context.CancelFunc
	done      chan struct{}
	scanID    string
	scanName  string
	counter   atomic.Int32
	TeamID    string
}

// NewUploadWriter creates a new upload writer
func NewUploadWriter(ctx context.Context, creds *pdcpauth.PDCPCredentials) (*UploadWriter, error) {
	if creds == nil {
		return nil, fmt.Errorf("no credentials provided")
	}
	u := &UploadWriter{
		creds:  creds,
		done:   make(chan struct{}, 1),
		TeamID: NoneTeamID,
	}
	var err error
	reader, writer := io.Pipe()
	// create standard writer
	u.StandardWriter, err = output.NewWriter(
		output.WithWriter(writer),
		output.WithJson(true, true),
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

	// create http client
	opts := retryablehttp.DefaultOptionsSingle
	opts.NoAdjustTimeout = true
	opts.Timeout = time.Duration(3) * time.Minute
	u.client = retryablehttp.NewClient(opts)

	// create context
	ctx, u.cancel = context.WithCancel(ctx)
	// start auto commit
	// upload every 1 minute or when buffer is full
	go u.autoCommit(ctx, reader)
	return u, nil
}

// SetScanID sets the scan id for the upload writer
func (u *UploadWriter) SetScanID(id string) error {
	if !xidRegex.MatchString(id) {
		return fmt.Errorf("invalid scan id provided")
	}
	u.scanID = id
	return nil
}

// SetScanName sets the scan name for the upload writer
func (u *UploadWriter) SetScanName(name string) {
	u.scanName = name
}

func (u *UploadWriter) SetTeamID(id string) {
	if id == "" {
		u.TeamID = NoneTeamID
	} else {
		u.TeamID = id
	}
}

func (u *UploadWriter) autoCommit(ctx context.Context, r *io.PipeReader) {
	reader := bufio.NewReader(r)
	ch := make(chan string, 4)

	// continuously read from the reader and send to channel
	go func() {
		defer r.Close()
		defer close(ch)
		for {
			data, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			u.counter.Add(1)
			ch <- data
		}
	}()

	// wait for context to be done
	defer func() {
		u.done <- struct{}{}
		close(u.done)
		// if no scanid is generated no results were uploaded
		if u.scanID == "" {
			gologger.Verbose().Msgf("Scan results upload to cloud skipped, no results found to upload")
		} else {
			gologger.Info().Msgf("%v Scan results uploaded to cloud, you can view scan results at %v", u.counter.Load(), getScanDashBoardURL(u.scanID, u.TeamID))
		}
	}()
	// temporary buffer to store the results
	buff := &bytes.Buffer{}
	ticker := time.NewTicker(flushTimer)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// flush before exit
			if buff.Len() > 0 {
				if err := u.uploadChunk(buff); err != nil {
					gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
				}
			}
			return
		case <-ticker.C:
			// flush the buffer
			if buff.Len() > 0 {
				if err := u.uploadChunk(buff); err != nil {
					gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
				}
			}
		case line, ok := <-ch:
			if !ok {
				if buff.Len() > 0 {
					if err := u.uploadChunk(buff); err != nil {
						gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
					}
				}
				return
			}
			if buff.Len()+len(line) > MaxChunkSize {
				// flush existing buffer
				if err := u.uploadChunk(buff); err != nil {
					gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
				}
			} else {
				buff.WriteString(line)
			}
		}
	}
}

// uploadChunk uploads a chunk of data to the server
func (u *UploadWriter) uploadChunk(buff *bytes.Buffer) error {
	if err := u.upload(buff.Bytes()); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not upload chunk")
	}
	// if successful, reset the buffer
	buff.Reset()
	// log in verbose mode
	gologger.Warning().Msgf("Uploaded results chunk, you can view scan results at %v", getScanDashBoardURL(u.scanID, u.TeamID))
	return nil
}

func (u *UploadWriter) upload(data []byte) error {
	req, err := u.getRequest(data)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not create upload request")
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not upload results")
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not get id from response")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not upload results got status code %v on %v", resp.StatusCode, resp.Request.URL.String())
	}
	var uploadResp uploadResponse
	if err := json.Unmarshal(bin, &uploadResp); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not unmarshal response got %v", string(bin))
	}
	if uploadResp.ID != "" && u.scanID == "" {
		u.scanID = uploadResp.ID
	}
	return nil
}

// getRequest returns a new request for upload
// if scanID is not provided create new scan by uploading the data
// if scanID is provided append the data to existing scan
func (u *UploadWriter) getRequest(bin []byte) (*retryablehttp.Request, error) {
	var method, url string

	if u.scanID == "" {
		u.uploadURL.Path = uploadEndpoint
		method = http.MethodPost
		url = u.uploadURL.String()
	} else {
		u.uploadURL.Path = fmt.Sprintf(appendEndpoint, u.scanID)
		method = http.MethodPatch
		url = u.uploadURL.String()
	}
	req, err := retryablehttp.NewRequest(method, url, bytes.NewReader(bin))
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create cloud upload request")
	}
	// add pdtm meta params
	req.URL.Params.Merge(updateutils.GetpdtmParams(config.Version))
	// if it is upload endpoint also include name if it exists
	if u.scanName != "" && req.URL.Path == uploadEndpoint {
		req.URL.Params.Add("name", u.scanName)
	}
	req.URL.Update()

	req.Header.Set(pdcpauth.ApiKeyHeaderName, u.creds.APIKey)
	if u.TeamID != NoneTeamID && u.TeamID != "" {
		req.Header.Set(teamIDHeader, u.TeamID)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Close closes the upload writer
func (u *UploadWriter) Close() {
	u.cancel()
	<-u.done
	u.StandardWriter.Close()
}
