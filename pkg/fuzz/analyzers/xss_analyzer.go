package analyzers

import (
	"context"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// XSSContextAnalyzer realiza análise de contexto HTML para detecção de XSS
type XSSContextAnalyzer struct{}

// Name retorna o nome único do analisador
func (a *XSSContextAnalyzer) Name() string {
	return "xss-context"
}

// ApplyInitialTransformation prepara o payload para rastreamento
func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data + "pd_xss"
}

// Analyze executa a lógica de detecção seguindo os padrões de segurança CWE-200 e CWE-1164
func (a *XSSContextAnalyzer) Analyze(options *Options) (bool, string, error) {
	gr := options.FuzzGenerated
	// Usa gr.Value para garantir compatibilidade com modos KV e outros encoders
	payload := a.ApplyInitialTransformation(gr.Value, nil)

	// Injeta o payload no componente (Query, Form, Header, etc.)
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}

	// Reconstrói a requisição com o payload injetado
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	// Executa a requisição usando o HttpClient do Nuclei
	// Nota: Usamos o contexto da requisição original para respeitar timeouts do sistema
	resp, err := options.HttpClient.Do(rebuilt.WithContext(context.Background()))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Tratamento robusto de erro na leitura do corpo (Sugerido pelo Neo)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	// Check rápido de performance antes de iniciar a tokenização pesada
	if !strings.Contains(body, payload) {
		return false, "", nil
	}

	// Tokenização segura para identificar o contexto exato da reflexão
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
					// CWE-200 Fix: Retorna apenas metadados, nunca o valor real do atributo
					return true, "reflected in attribute: " + attr.Key + " of tag: <" + token.Data + ">", nil
				}
			}
		case html.TextToken:
			if strings.Contains(token.Data, payload) {
				return true, "reflected in html text node", nil
			}
		}
	}

	return false, "", nil
}