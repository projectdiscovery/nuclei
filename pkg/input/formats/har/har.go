package har

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// HARFormat is an HTTP Archive (HAR 1.2) parser, the format browsers and
// proxies export captured traffic in.
type HARFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new HAR parser
func New() *HARFormat {
	return &HARFormat{}
}

var _ formats.Format = &HARFormat{}

type archive struct {
	Log struct {
		Entries []entry `json:"entries"`
	} `json:"log"`
}

type entry struct {
	Request struct {
		Method   string   `json:"method"`
		URL      string   `json:"url"`
		Headers  []header `json:"headers"`
		PostData *struct {
			Text string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status     int      `json:"status"`
		StatusText string   `json:"statusText"`
		Headers    []header `json:"headers"`
		Content    struct {
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Name returns the name of the format
func (h *HARFormat) Name() string {
	return "har"
}

func (h *HARFormat) SetOptions(options formats.InputFormatOptions) {
	h.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (h *HARFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	var har archive
	if err := json.NewDecoder(input).Decode(&har); err != nil {
		return errors.Wrap(err, "could not decode har file")
	}

	for _, e := range har.Log.Entries {
		// Browsers also log data:, blob: and extension URLs, which have no
		// host to send a request to.
		if !strings.HasPrefix(e.Request.URL, "http://") && !strings.HasPrefix(e.Request.URL, "https://") {
			continue
		}
		rawRequest, err := types.ParseRawRequestWithURL(rawRequestOf(e), e.Request.URL)
		if err != nil {
			gologger.Warning().Msgf("har: Could not parse request %s: %s\n", e.Request.URL, err)
			continue
		}
		// Status 0 is a request that was blocked or never answered.
		if e.Response.Status != 0 {
			rawRequest.Response = &types.HttpResponse{Raw: rawResponseOf(e)}
		}
		resultsCb(rawRequest)
	}
	return nil
}

// rawRequestOf rebuilds the request as HTTP/1.1 with an absolute target, which
// carries the authority that HTTP/2 captures only keep in pseudo-headers.
func rawRequestOf(e entry) string {
	var b strings.Builder
	b.WriteString(e.Request.Method + " " + e.Request.URL + " HTTP/1.1\r\n")
	writeHeaders(&b, e.Request.Headers)
	if e.Request.PostData != nil {
		b.WriteString(e.Request.PostData.Text)
	}
	return b.String()
}

func rawResponseOf(e entry) string {
	statusText := e.Response.StatusText
	if statusText == "" {
		statusText = http.StatusText(e.Response.Status)
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(e.Response.Status) + " " + statusText + "\r\n")
	writeHeaders(&b, e.Response.Headers)
	body := e.Response.Content.Text
	if e.Response.Content.Encoding == "base64" {
		if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
			body = string(decoded)
		}
	}
	b.WriteString(body)
	return b.String()
}

func writeHeaders(b *strings.Builder, headers []header) {
	for _, h := range headers {
		// HTTP/2 pseudo-headers (:authority, :path, ...) are not headers.
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		b.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	b.WriteString("\r\n")
}
