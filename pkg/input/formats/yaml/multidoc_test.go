package yaml

import (
	"os"
	"testing"

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
	defer file.Close()

	var urls []string
	err = format.Parse(file, func(request *types.RequestResponse) bool {
		urls = append(urls, request.URL.String())
		return false
	}, proxifyInputFile)
	require.Nilf(t, err, "error parsing yaml file: %v", err)
	require.Len(t, urls, len(expectedUrls), "invalid number of urls")
	require.ElementsMatch(t, urls, expectedUrls, "invalid urls")
}
