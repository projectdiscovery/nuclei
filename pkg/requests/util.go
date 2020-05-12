package requests

import (
	"fmt"
	"math/rand"
	"strings"
)

func newReplacer(values map[string]interface{}) *strings.Replacer {
	var replacerItems []string
	for k, v := range values {
		replacerItems = append(replacerItems, fmt.Sprintf("{{%s}}", k))
		replacerItems = append(replacerItems, fmt.Sprintf("%s", v))
	}

	return strings.NewReplacer(replacerItems...)
}

func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0987654321")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
