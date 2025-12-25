package headless

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestRequest_ExtractXPath(t *testing.T) {
	request := &Request{}

	// Test HTML content extraction
	htmlContent := `<!doctype html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <div class="container">
        <h1>Welcome</h1>
        <p>This is a test page</p>
        <a href="https://example.com" id="test-link">Click here</a>
        <ul>
            <li>Item 1</li>
            <li>Item 2</li>
            <li>Item 3</li>
        </ul>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"data": htmlContent,
	}

	// Test extracting text content
	extractor := &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/div/h1"},
	}
	err := extractor.CompileExtractors()
	require.Nil(t, err)

	result := request.Extract(data, extractor)
	expected := map[string]struct{}{"Welcome": {}}
	require.Equal(t, expected, result)

	// Test extracting attribute value
	extractor = &extractors.Extractor{
		Type:      extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath:     []string{"/html/body/div/a"},
		Attribute: "href",
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{"https://example.com": {}}
	require.Equal(t, expected, result)

	// Test extracting multiple items
	extractor = &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/div/ul/li"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"Item 1": {},
		"Item 2": {},
		"Item 3": {},
	}
	require.Equal(t, expected, result)

	// Test with non-existent XPath
	extractor = &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/div/nonexistent"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	require.Equal(t, map[string]struct{}{}, result)
}

func TestRequest_ExtractJSON(t *testing.T) {
	request := &Request{}

	// Test JSON content extraction
	jsonContent := `{
		"users": [
			{"id": 1, "name": "John", "email": "john@example.com"},
			{"id": 2, "name": "Jane", "email": "jane@example.com"},
			{"id": 3, "name": "Bob", "email": "bob@example.com"}
		],
		"metadata": {
			"total": 3,
			"page": 1
		}
	}`

	data := map[string]interface{}{
		"data": jsonContent,
	}

	// Test extracting user IDs
	extractor := &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".users[].id"},
	}
	err := extractor.CompileExtractors()
	require.Nil(t, err)

	result := request.Extract(data, extractor)
	expected := map[string]struct{}{
		"1": {},
		"2": {},
		"3": {},
	}
	require.Equal(t, expected, result)

	// Test extracting user names
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".users[].name"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"John": {},
		"Jane": {},
		"Bob":  {},
	}
	require.Equal(t, expected, result)

	// Test extracting nested values
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".metadata.total"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{"3": {}}
	require.Equal(t, expected, result)

	// Test extracting emails
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".users[].email"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"john@example.com": {},
		"jane@example.com": {},
		"bob@example.com":  {},
	}
	require.Equal(t, expected, result)

	// Test with invalid JSON
	invalidJSON := `{"invalid": json}`
	data = map[string]interface{}{
		"data": invalidJSON,
	}

	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".invalid"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	require.Equal(t, map[string]struct{}{}, result)

	// Test with non-existent path
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".nonexistent"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	require.Equal(t, map[string]struct{}{}, result)
}

func TestRequest_MatchXPath(t *testing.T) {
	request := &Request{}

	htmlContent := `<!doctype html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <div class="container">
        <h1>Welcome</h1>
        <p>This is a test page</p>
        <a href="https://example.com" id="test-link">Click here</a>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"data": htmlContent,
	}

	// Test XPath matcher with existing element
	matcher := &matchers.Matcher{
		Type:      matchers.MatcherTypeHolder{MatcherType: matchers.XPathMatcher},
		XPath:     []string{"/html/body/div/h1"},
		Condition: "and",
	}
	err := matcher.CompileMatchers()
	require.Nil(t, err)

	matched, snippets := request.Match(data, matcher)
	require.True(t, matched)
	require.Empty(t, snippets)

	// Test XPath matcher with non-existent element
	matcher = &matchers.Matcher{
		Type:      matchers.MatcherTypeHolder{MatcherType: matchers.XPathMatcher},
		XPath:     []string{"/html/body/div/nonexistent"},
		Condition: "and",
	}
	err = matcher.CompileMatchers()
	require.Nil(t, err)

	matched, snippets = request.Match(data, matcher)
	require.False(t, matched)
	require.Empty(t, snippets)
}

func TestRequest_getMatchPart(t *testing.T) {
	request := &Request{}

	data := map[string]interface{}{
		"data":    "body content",
		"header":  "header content",
		"history": "history content",
	}

	// Test default part (should map to "data")
	part, ok := request.getMatchPart("", data)
	require.True(t, ok)
	require.Equal(t, "body content", part)

	// Test "body" part (should map to "data")
	part, ok = request.getMatchPart("body", data)
	require.True(t, ok)
	require.Equal(t, "body content", part)

	// Test "resp" part (should map to "data")
	part, ok = request.getMatchPart("resp", data)
	require.True(t, ok)
	require.Equal(t, "body content", part)

	// Test "header" part
	part, ok = request.getMatchPart("header", data)
	require.True(t, ok)
	require.Equal(t, "header content", part)

	// Test "history" part
	part, ok = request.getMatchPart("history", data)
	require.True(t, ok)
	require.Equal(t, "history content", part)

	// Test non-existent part
	part, ok = request.getMatchPart("nonexistent", data)
	require.False(t, ok)
	require.Equal(t, "", part)
}

func TestRequest_ExtractWithDifferentParts(t *testing.T) {
	request := &Request{}

	// Test extracting from different parts
	htmlContent := `<!doctype html><html><body><div><h1>Title</h1></div></body></html>`
	jsonContent := `{"id": 123}`

	data := map[string]interface{}{
		"data":    htmlContent,
		"header":  jsonContent,
		"history": htmlContent,
	}

	// Test XPath extractor from "data" part
	extractor := &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/div/h1"},
		Part:  "data",
	}
	err := extractor.CompileExtractors()
	require.Nil(t, err)

	result := request.Extract(data, extractor)
	expected := map[string]struct{}{"Title": {}}
	require.Equal(t, expected, result)

	// Test JSON extractor from "header" part
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".id"},
		Part: "header",
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{"123": {}}
	require.Equal(t, expected, result)

	// Test XPath extractor from "history" part
	extractor = &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/div/h1"},
		Part:  "history",
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{"Title": {}}
	require.Equal(t, expected, result)
}

func TestRequest_ExtractWithComplexJSON(t *testing.T) {
	request := &Request{}

	// Test with complex nested JSON structure
	jsonContent := `{
		"api": {
			"version": "1.0",
			"endpoints": [
				{
					"path": "/users",
					"method": "GET",
					"responses": [
						{"code": 200, "description": "Success"},
						{"code": 404, "description": "Not Found"}
					]
				},
				{
					"path": "/posts",
					"method": "POST",
					"responses": [
						{"code": 201, "description": "Created"},
						{"code": 400, "description": "Bad Request"}
					]
				}
			]
		}
	}`

	data := map[string]interface{}{
		"data": jsonContent,
	}

	// Test extracting API version
	extractor := &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".api.version"},
	}
	err := extractor.CompileExtractors()
	require.Nil(t, err)

	result := request.Extract(data, extractor)
	expected := map[string]struct{}{"1.0": {}}
	require.Equal(t, expected, result)

	// Test extracting all endpoint paths
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".api.endpoints[].path"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"/users": {},
		"/posts": {},
	}
	require.Equal(t, expected, result)

	// Test extracting all response codes
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".api.endpoints[].responses[].code"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"200": {},
		"404": {},
		"201": {},
		"400": {},
	}
	require.Equal(t, expected, result)

	// Test extracting response descriptions
	extractor = &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.JSONExtractor},
		JSON: []string{".api.endpoints[].responses[].description"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"Success":     {},
		"Not Found":   {},
		"Created":     {},
		"Bad Request": {},
	}
	require.Equal(t, expected, result)
}

func TestRequest_ExtractWithComplexHTML(t *testing.T) {
	request := &Request{}

	// Test with complex HTML structure
	htmlContent := `<!doctype html>
<html>
<head>
    <title>E-commerce Site</title>
    <meta name="description" content="Online shopping platform">
</head>
<body>
    <header>
        <nav>
            <ul class="nav-menu">
                <li><a href="/home">Home</a></li>
                <li><a href="/products">Products</a></li>
                <li><a href="/about">About</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <section class="products">
            <h2>Featured Products</h2>
            <div class="product-grid">
                <div class="product" data-id="1">
                    <h3>Laptop</h3>
                    <p class="price">$999</p>
                    <span class="rating">4.5</span>
                </div>
                <div class="product" data-id="2">
                    <h3>Phone</h3>
                    <p class="price">$599</p>
                    <span class="rating">4.2</span>
                </div>
                <div class="product" data-id="3">
                    <h3>Tablet</h3>
                    <p class="price">$399</p>
                    <span class="rating">4.0</span>
                </div>
            </div>
        </section>
    </main>
    <footer>
        <p>&copy; 2024 E-commerce Site</p>
    </footer>
</body>
</html>`

	data := map[string]interface{}{
		"data": htmlContent,
	}

	// Test extracting navigation links
	extractor := &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/header/nav/ul/li/a"},
	}
	err := extractor.CompileExtractors()
	require.Nil(t, err)

	result := request.Extract(data, extractor)
	expected := map[string]struct{}{
		"Home":     {},
		"Products": {},
		"About":    {},
	}
	require.Equal(t, expected, result)

	// Test extracting product names
	extractor = &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/main/section/div/div/h3"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"Laptop": {},
		"Phone":  {},
		"Tablet": {},
	}
	require.Equal(t, expected, result)

	// Test extracting product prices
	extractor = &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/main/section/div/div/p[@class='price']"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"$999": {},
		"$599": {},
		"$399": {},
	}
	require.Equal(t, expected, result)

	// Test extracting product ratings
	extractor = &extractors.Extractor{
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath: []string{"/html/body/main/section/div/div/span[@class='rating']"},
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"4.5": {},
		"4.2": {},
		"4.0": {},
	}
	require.Equal(t, expected, result)

	// Test extracting data attributes
	extractor = &extractors.Extractor{
		Type:      extractors.ExtractorTypeHolder{ExtractorType: extractors.XPathExtractor},
		XPath:     []string{"/html/body/main/section/div/div[@class='product']"},
		Attribute: "data-id",
	}
	err = extractor.CompileExtractors()
	require.Nil(t, err)

	result = request.Extract(data, extractor)
	expected = map[string]struct{}{
		"1": {},
		"2": {},
		"3": {},
	}
	require.Equal(t, expected, result)
}
