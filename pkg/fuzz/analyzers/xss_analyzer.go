package analyzers

import (
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/net/html"
)

// Constants for standardization and maintenance
const (
	XSSAnalyzerName = "xss-context"
	MaxResponseSize = 4 * 1024 * 1024 // 4MB
	CanaryLength    = 6
)

type XSSContextAnalyzer struct{}

func (a *XSSContextAnalyzer) Name() string {
	return XSSAnalyzerName
}

func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// randStringBytesMask is a utility function from the analyzers package
	return data + randStringBytesMask(CanaryLength)
}

func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.Value, nil)

	// Inject payload and ensure mandatory state restoration (Component Contract)
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", fmt.Errorf("failed to set fuzz value: %w", err)
	}
	defer func() {
		if err := gr.Component.SetValue(gr.Key, gr.Value); err != nil {
			log.Printf("[%s] critical: failed to restore component state: %v", XSSAnalyzerName, err)
		}
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", fmt.Errorf("failed to rebuild request: %w", err)
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// Safety limit reading + 1 byte to detect explicit truncation
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return false, "", fmt.Errorf("failed to read response body: %w", err)
	}
	if len(bodyBytes) > MaxResponseSize {
		return false, "", fmt.Errorf("response body exceeded limit of %d bytes", MaxResponseSize)
	}

	return a.analyzeContent(strings.NewReader(string(bodyBytes)), payload)
}

// analyzeContent processes HTML via Tokenizer to identify the reflection context
func (a *XSSContextAnalyzer) analyzeContent(r io.Reader, payload string) (bool, string, error) {
	tokenizer := html.NewTokenizer(r)

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			if err := tokenizer.Err(); err != io.EOF {
				return false, "", err
			}
			break
		}

		token := tokenizer.Token()
		// Raw content of the token (text or comment data)
		content := token.Data

		switch tokenType {
		case html.StartTagToken, html.SelfClosingTagToken:
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, payload) {
					return true, fmt.Sprintf("reflection in attribute: %s (tag: <%s>)", attr.Key, token.Data), nil
				}
			}

		case html.CommentToken:
			if strings.Contains(content, payload) {
				return true, "reflection in html comment", nil
			}

		case html.TextToken:
			if strings.Contains(content, payload) {
				return true, "reflection in html text node", nil
			}
		}
	}

	return false, "", nil
}