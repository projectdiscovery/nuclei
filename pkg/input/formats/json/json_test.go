package json

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

var expectedURLs = []string{
	"https://ginandjuice.shop/",
	"https://ginandjuice.shop/catalog/product?productId=1",
	"https://ginandjuice.shop/resources/js/stockCheck.js",
	"https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js",
	"https://ginandjuice.shop/resources/js/xmlStockCheckPayload.js",
	"https://ginandjuice.shop/resources/js/stockCheck.js",
	"https://ginandjuice.shop/catalog/product/stock",
	"https://ginandjuice.shop/catalog/cart",
	"https://ginandjuice.shop/catalog/product?productId=1",
	"https://ginandjuice.shop/catalog/subscribe",
	"https://ginandjuice.shop/blog",
	"https://ginandjuice.shop/blog/?search=dadad&back=%2Fblog%2F",
	"https://ginandjuice.shop/logger",
	"https://ginandjuice.shop/blog/",
	"https://ginandjuice.shop/blog/post?postId=3",
	"https://ginandjuice.shop/about",
	"https://ginandjuice.shop/my-account",
	"https://ginandjuice.shop/login",
	"https://ginandjuice.shop/login",
	"https://ginandjuice.shop/login",
	"https://ginandjuice.shop/my-account",
	"https://ginandjuice.shop/catalog/cart",
	"https://ginandjuice.shop/my-account",
	"https://ginandjuice.shop/logout",
	"https://ginandjuice.shop/",
	"https://ginandjuice.shop/catalog",
}

func TestJSONFormatterParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/ginandjuice.proxify.json"

	var urls []string
	err := format.Parse(proxifyInputFile, func(request *types.RequestResponse) bool {
		urls = append(urls, request.URL.String())
		return false
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(urls) != len(expectedURLs) {
		t.Fatalf("invalid number of urls: %d", len(urls))
	}
	require.ElementsMatch(t, urls, expectedURLs)
}
