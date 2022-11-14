package analyzers

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// AnalyzeHTMLContext takes a probe for xss and returns the contexts
// it landed in for the DOM of the page.
func AnalyzeHTMLContext(prefix, characters, suffix, response string) {
	tokenizeHTMLDiscoverContexts(prefix, response)
}

// context is the discovered context for a XSS payload
type context struct {
	tag         string
	contextType contextType
}

// contextType is the type of context
type contextType int

// tokenizeHTMLDiscoverContexts performs tokenization of response using go html parser
func tokenizeHTMLDiscoverContexts(prefix, response string) {
	tokenizer := html.NewTokenizer(strings.NewReader(response))

	var previous html.Token
	for {
		tokenType := tokenizer.Next()
		token := tokenizer.Token()
		if tokenType == html.ErrorToken {
			break
		}
		//tokenStr := token.String()
		if strings.Contains(token.String(), prefix) {
			switch tokenType {
			case html.StartTagToken:

			case html.TextToken:
				if previous.Type == html.StartTagToken {
					switch previous.Data {
					case "script":

					case "style":

					case "noscript":

					}
				}
				fmt.Printf("%v\n", trimString(token.String()))

			case html.CommentToken:
			}
			//fmt.Printf("Token: type: %v %v raw: %v (Previous: %+v)\n", tokenType, trimString(tokenStr), trimString(string(tokenizer.Raw())), trimString(previous.String()))
		}
		previous = token
	}
}

func trimString(value string) string {
	return html.UnescapeString(strings.ReplaceAll(value, "\n", ""))
}
