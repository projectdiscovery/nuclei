package analyzers

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// XSSContextAnalyzer represents an analyzer that detects the context of an XSS reflection.
type XSSContextAnalyzer struct{}

// Name returns the unique identifier for the XSS context analyzer.
func (a *XSSContextAnalyzer) Name() string {
	return "xss-context"
}

// ApplyInitialTransformation appends a unique canary string to the input data for tracking reflections.
func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data + "pd_xss"
}

// Analyze executes the fuzzing request and parses the HTML response to identify if the canary 
// reflects within an HTML text node or a tag attribute.
func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	resp, err := options.HttpClient.Do(options.FuzzGenerated.Request)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Capture and handle body read errors to avoid silent failures.
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	
	body := string(bodyBytes)
	canary := "pd_xss"

	// Quick check for canary presence before starting heavy tokenization.
	if !strings.Contains(body, canary) {
		return false, "", nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			err := tokenizer.Err()
			if err == io.EOF {
				break
			}
			return false, "", err
		}

		token := tokenizer.Token()

		switch tokenType {
		case html.StartTagToken, html.SelfClosingTagToken:
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, canary) {
					return true, "attr:" + attr.Key + ":" + token.Data, nil
				}
			}
		case html.TextToken:
			if strings.Contains(token.Data, canary) {
				return true, "text:" + token.Data, nil
			}
		}
	}

	return true, "reflected:unknown", nil
}

func init() {
	RegisterAnalyzer("xss-context", &XSSContextAnalyzer{})
}