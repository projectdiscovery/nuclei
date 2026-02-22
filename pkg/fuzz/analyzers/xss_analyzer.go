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
	// CodeRabbit Fix: Usar gr.Value para garantir compatibilidade com todos os modos de fuzzing
	payload := a.ApplyInitialTransformation(gr.Value, nil)

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Neo Fix: Tratamento correto de erro na leitura do corpo
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	if !strings.Contains(body, payload) {
		return false, "", nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		token := tokenizer.Token()
		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken {
			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, payload) {
					return true, "attr:" + attr.Key + ":" + token.Data, nil
				}
			}
		} else if tokenType == html.TextToken {
			if strings.Contains(token.Data, payload) {
				return true, "text:" + token.Data, nil
			}
		}
	}
	return false, "", nil
}