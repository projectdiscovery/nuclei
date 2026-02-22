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
	gr := options.FuzzGenerated

	// 1. Gera o payload com o canário "pd_xss"
	payload := a.ApplyInitialTransformation(gr.OriginalPayload, options.AnalyzerParameters)

	// 2. Define o valor no componente (URL, Body, etc.) conforme exigido pelo CodeRabbit
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}

	// 3. Reconstrói a requisição com o payload injetado para não enviar a requisição limpa
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	// 4. Executa a requisição reconstruída
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Tratamento de erro na leitura para evitar falhas silenciosas (exigência do Neo/CodeRabbit)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	
	body := string(bodyBytes)
	canary := "pd_xss"

	// Otimização: verifica presença simples antes do parsing de HTML
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
					// Identifica reflexão em atributos
					return true, "attr:" + attr.Key + ":" + token.Data, nil
				}
			}
		case html.TextToken:
			if strings.Contains(token.Data, canary) {
				// Identifica reflexão em nós de texto
				return true, "text:" + token.Data, nil
			}
		}
	}

	return true, "reflected:unknown", nil
}

func init() {
	RegisterAnalyzer("xss-context", &XSSContextAnalyzer{})
}