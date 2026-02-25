package analyzers

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

type XSSContextAnalyzer struct{}

const xssCanaryMarker = "pd_xss"

func (a *XSSContextAnalyzer) Name() string {
	return "xss-context"
}

// ApplyInitialTransformation appends a marker to track reflection.
func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data + xssCanaryMarker
}

func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	if options == nil || options.HttpClient == nil || options.FuzzGenerated.Request == nil {
		return false, "", nil
	}

	resp, err := options.HttpClient.Do(options.FuzzGenerated.Request)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	const maxBodySize = 4 * 1024 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return false, "", err
	}

	body := string(bodyBytes)
	canary := xssCanaryMarker
	if value := options.FuzzGenerated.Value; value != "" {
		if strings.Contains(value, xssCanaryMarker) {
			canary = xssCanaryMarker
		} else {
			canary = value
		}
	}

	if !strings.Contains(body, canary) {
		return false, "", nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	tagDepth := 0

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		token := tokenizer.Token()
		switch tokenType {
		case html.StartTagToken:
			tagDepth++
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, canary) {
					return true, "attr:" + attr.Key + ":" + token.Data, nil
				}
			}
		case html.SelfClosingTagToken:
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, canary) {
					return true, "attr:" + attr.Key + ":" + token.Data, nil
				}
			}
		case html.EndTagToken:
			if tagDepth > 0 {
				tagDepth--
			}
		case html.TextToken:
			if tagDepth > 0 && strings.Contains(token.Data, canary) {
				return true, "text:" + token.Data, nil
			}
		}
	}

	return true, "reflected:unknown", nil
}

func init() {
	RegisterAnalyzer("xss-context", &XSSContextAnalyzer{})
}