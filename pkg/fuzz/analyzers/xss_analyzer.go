package analyzers

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

type XSSContextAnalyzer struct{}

func (a *XSSContextAnalyzer) Name() string {
	return "xss-context"
}

func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data + "pd_xss"
}

func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.Value, nil)

	// Set mutated value
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}
	// Restore original value on exit to satisfy the component contract
	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.Value)
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	// Use the context from the rebuilt request
	resp, err := options.HttpClient.Do(rebuilt.WithContext(rebuilt.Context()))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	// Context analysis using HTML tokenization
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
					return true, "reflection in attribute: " + attr.Key + " of tag: <" + token.Data + ">", nil
				}
			}
		case html.TextToken:
			if strings.Contains(token.Data, payload) {
				return true, "reflection in html text node", nil
			}
		}
	}

	return false, "", nil
}