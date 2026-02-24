package analyzers

import (
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/net/html"
)

type XSSContextAnalyzer struct{}

func (a *XSSContextAnalyzer) Name() string {
	return "xss-context"
}

func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// Use randomized canary to avoid false positives (standard in Nuclei)
	return data + randStringBytesMask(6)
}

func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.Value, nil)

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}
	// Log error if restoration fails to maintain component integrity
	defer func() {
		if err := gr.Component.SetValue(gr.Key, gr.Value); err != nil {
			log.Printf("[xss-analyzer] failed to restore value for %s: %v", gr.Key, err)
		}
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	// Use request directly (removed redundant WithContext)
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Limit reading to 4MB to prevent OOM
	const maxBodySize = 4 * 1024 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			if err := tokenizer.Err(); err != io.EOF {
				return false, "", err
			}
			break
		}

		token := tokenizer.Token()
		switch tokenType {
		case html.StartTagToken, html.SelfClosingTagToken:
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, payload) {
					return true, fmt.Sprintf("reflection in attribute: %s of tag: <%s>", attr.Key, token.Data), nil
				}
			}
		case html.TextToken:
			if strings.Contains(token.Data, payload) {
				return true, "reflection in html text node", nil
			}
		case html.CommentToken: // Added per Neo/CodeRabbit suggestion
			if strings.Contains(token.Data, payload) {
				return true, "reflection in html comment", nil
			}
		}
	}

	return false, "", nil
}