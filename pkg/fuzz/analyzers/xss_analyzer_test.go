package analyzers

import (
	"testing"
	"strings"

	"golang.org/x/net/html"
	"github.com/stretchr/testify/assert"
)

func TestXSSContextAnalyzer(t *testing.T) {
	t.Run("text-context", func(t *testing.T) {
		body := "<div>pd_xss</div>"
		canary := "pd_xss"
		found := false

		tokenizer := html.NewTokenizer(strings.NewReader(body))
		for {
			tokenType := tokenizer.Next()
			if tokenType == html.ErrorToken {
				break
			}
			token := tokenizer.Token()
			if tokenType == html.TextToken && strings.Contains(token.Data, canary) {
				found = true
				break
			}
		}
		assert.True(t, found, "Deveria detectar o reflexo no texto")
	})

	t.Run("attribute-context", func(t *testing.T) {
		body := `<input value="pd_xss">`
		canary := "pd_xss"
		found := false

		tokenizer := html.NewTokenizer(strings.NewReader(body))
		for {
			tokenType := tokenizer.Next()
			if tokenType == html.ErrorToken {
				break
			}
			token := tokenizer.Token()
			if (tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken) {
				for _, attr := range token.Attr {
					if strings.Contains(attr.Val, canary) {
						found = true
						break
					}
				}
			}
		}
		assert.True(t, found, "Deveria detectar o reflexo no atributo")
	})
}