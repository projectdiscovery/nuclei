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
	resp, err := options.HttpClient.Do(options.FuzzGenerated.Request)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)
	canary := "pd_xss"

	if !strings.Contains(body, canary) {
		return false, "", nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
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