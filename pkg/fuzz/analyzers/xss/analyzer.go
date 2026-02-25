package xss

import (
	"bytes"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"golang.org/x/net/html"
)

// Analyzer checks for XSS reflection and its context in the HTTP response
type Analyzer struct{}

// Ensure the Analyzer interface is fully implemented at compile time
var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name is the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation fulfills the Analyzer interface requirement
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data
}

// Analyze sends the request and checks for payload reflection context securely
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil {
		return false, "", nil
	}

	// Set the fuzz value on the component before rebuilding
	if err := options.FuzzGenerated.Component.SetValue(
		options.FuzzGenerated.Key,
		options.FuzzGenerated.Value,
	); err != nil {
		return false, "", errors.Wrap(err, "could not set component value")
	}

	req, err := options.FuzzGenerated.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request")
	}

	resp, err := options.HttpClient.Do(req)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send request")
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", errors.Wrap(err, "could not read response body")
	}
	bodyStr := string(bodyBytes)

	payload := options.FuzzGenerated.Value

	if payload == "" || !strings.Contains(bodyStr, payload) {
		return false, "", nil
	}

	context := determineContext(bodyBytes, payload)

	return true, "Reflected Context: " + context, nil
}

// determineContext parses HTML nodes to pinpoint the exact location of the payload reflection
func determineContext(body []byte, payload string) string {
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		token := tokenizer.Token()

		switch tt {
		case html.TextToken:
			if strings.Contains(token.Data, payload) {
				return "HTML Text"
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			for _, attr := range token.Attr {
				if strings.Contains(attr.Key, payload) {
					return "Attribute Name (" + token.Data + ")"
				}
				if strings.Contains(attr.Val, payload) {
					return "Attribute Value (" + token.Data + "[" + attr.Key + "])"
				}
			}

			if token.Data == "script" {
				ttNext := tokenizer.Next()
				if ttNext == html.TextToken {
					if strings.Contains(tokenizer.Token().Data, payload) {
						return "Script Block"
					}
				}
			}
		case html.CommentToken:
			if strings.Contains(token.Data, payload) {
				return "HTML Comment"
			}
		}
	}

	return "Unknown Context"
}
