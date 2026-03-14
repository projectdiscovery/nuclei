package xss

import (
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"golang.org/x/net/html"
)

type XSSContextAnalyzer struct{}

var _ analyzers.Analyzer = &XSSContextAnalyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &XSSContextAnalyzer{})
}

func (a *XSSContextAnalyzer) Name() string {
	return "xss_context"
}

func (a *XSSContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data
}

func (a *XSSContextAnalyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	req := options.FuzzGenerated.Request

	resp, err := options.HttpClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	marker := options.FuzzGenerated.Value

	if !strings.Contains(body, marker) {
		return false, "", nil
	}

	context := FindContext(body, marker)

	return true, context, nil
}

// FindContext determines the reflection context of a marker within an HTML body
func FindContext(body string, marker string) string {
	z := html.NewTokenizer(strings.NewReader(body))

	for {
		tt := z.Next()

		if tt == html.ErrorToken {
			break
		}

		token := z.Token()

		switch tt {
		case html.TextToken:
			if strings.Contains(token.Data, marker) {
				return "html_text"
			}

		case html.CommentToken:
			if strings.Contains(token.Data, marker) {
				return "html_comment"
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tag := token.Data

			for _, attr := range token.Attr {
				if strings.Contains(attr.Val, marker) {
					name := strings.ToLower(attr.Key)

					if strings.HasPrefix(name, "on") {
						return "event_handler"
					}

					if name == "href" || name == "src" {
						return "url_attribute"
					}

					return "html_attribute"
				}
			}

			if tag == "script" {
				// Read script content and check for marker
				if z.Next() == html.TextToken {
					scriptContent := z.Token().Data
					if strings.Contains(scriptContent, marker) {
						// Check for type="application/json" etc.
						for _, attr := range token.Attr {
							if strings.ToLower(attr.Key) == "type" {
								val := strings.ToLower(attr.Val)
								if val == "application/json" || val == "application/ld+json" || val == "text/json" {
									return "script_data"
								}
							}
						}
						return "script_executable"
					}
				}
			}

			if tag == "style" {
				// Read style content and check for marker
				if z.Next() == html.TextToken {
					styleContent := z.Token().Data
					if strings.Contains(styleContent, marker) {
						return "style"
					}
				}
			}
		}
	}

	return "unknown"
}

