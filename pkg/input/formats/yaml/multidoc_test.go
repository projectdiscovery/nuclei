package yaml

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestYamlFormatterParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/ginandjuice.proxify.yaml"

	expectedUrls := []string{
		"https://ginandjuice.shop/blog/post?postId=3&source=proxify",
		"https://ginandjuice.shop/users/3",
	}

	file, err := os.Open(proxifyInputFile)
	require.Nilf(t, err, "error opening proxify input file: %v", err)
	defer func() {
		_ = file.Close()
	}()

	var urls []string
	err = format.Parse(file, func(request *types.RequestResponse) bool {
		urls = append(urls, request.URL.String())
		return false
	}, proxifyInputFile)
	require.Nilf(t, err, "error parsing yaml file: %v", err)
	require.Len(t, urls, len(expectedUrls), "invalid number of urls")
	require.ElementsMatch(t, urls, expectedUrls, "invalid urls")
}

func TestYamlFormatterParseWithVariables(t *testing.T) {
	format := New()
	proxifyYttFile := "../testdata/ytt/ginandjuice.ytt.yaml"

	expectedUrls := []string{
		"https://ginandjuice.shop/users/3",
	}

	format.SetOptions(formats.InputFormatOptions{
		VarsTextTemplating: true,
		Variables: map[string]interface{}{
			"foo": "catalog",
			"bar": "product",
		},
	})
	file, err := os.Open(proxifyYttFile)
	require.Nilf(t, err, "error opening proxify ytt input file: %v", err)
	defer file.Close()

	var urls []string
	err = format.Parse(file, func(request *types.RequestResponse) bool {
		urls = append(urls, request.URL.String())
		expectedRaw := `POST /users/3 HTTP/1.1
Host: ginandjuice.shop
Authorization: Bearer 3x4mpl3t0k3n
Accept-Encoding: gzip
Content-Type: application/x-www-form-urlencoded
Connection: close
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36

foo="catalog"&bar=product&debug=false`
		normalised := strings.ReplaceAll(request.Request.Raw, "\r\n", "\n")
		require.Equal(t, expectedRaw, strings.TrimSuffix(normalised, "\n"), "request raw does not match expected value")

		return false
	}, proxifyYttFile)

	require.Nilf(t, err, "error parsing yaml file: %v", err)
	require.Len(t, urls, len(expectedUrls), "invalid number of urls")
	require.ElementsMatch(t, urls, expectedUrls, "invalid urls")

}
