package analyzers

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// XSSContextAnalyzer detecta reflexões de payload em contextos HTML específicos.
type XSSContextAnalyzer struct{}

func (a *XSSContextAnalyzer) Name() string {
	return "xss-context"
}

// ApplyInitialTransformation adiciona um identificador único ao payload.
func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data + "pd_xss"
}

// Analyze executa a lógica de análise de reflexão no corpo da resposta.
func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.OriginalPayload, nil)

	// Injeta o payload no componente da requisição.
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}

	// Reconstrói a requisição no formato retryablehttp.
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	// Executa a requisição HTTP.
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Tratando o erro de leitura conforme sugerido pelo Neo.
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	// Verificação preliminar rápida.
	if !strings.Contains(body, payload) {
		return false, "", nil
	}

	// Tokenização HTML segura.
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