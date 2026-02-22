package analyzers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/stretchr/testify/require"
)

func TestXSSContextAnalyzer(t *testing.T) {
	analyzer := &XSSContextAnalyzer{}

	t.Run("body-context", func(t *testing.T) {
		body := `<html><body><div>pd_xss</div></body></html>`
		tokenizer := fuzz.NewHTMLTokenizer(strings.NewReader(body))
		
		found := false
		for {
			tokenType, err := tokenizer.Next()
			if err != nil {
				break
			}
			if tokenType == fuzz.TextToken && strings.Contains(tokenizer.Token().Data, "pd_xss") {
				found = true
				break
			}
		}
		require.True(t, found)
	})

	t.Run("attribute-context", func(t *testing.T) {
		body := `<html><body><input value="pd_xss"></body></html>`
		tokenizer := fuzz.NewHTMLTokenizer(strings.NewReader(body))
		
		found := false
		for {
			tokenType, err := tokenizer.Next()
			if err != nil {
				break
			}
			if tokenType == fuzz.StartTagToken {
				for _, attr := range tokenizer.Token().Attr {
					if strings.Contains(attr.Val, "pd_xss") {
						found = true
						break
					}
				}
			}
		}
		require.True(t, found)
	})
}