package fuzzing

var defaultPartsConfig = map[string]*AnalyzerPartsConfig{
	"headers": &AnalyzerPartsConfig{},
}

// defaultIgnoredHeaders contains a default list of headers that should
// not be fuzzed by the engine.
var defaultIgnoredHeaders = map[string]struct{}{
	"Accept-Charset":                 {},
	"Accept-Datetime":                {},
	"Accept-Encoding":                {},
	"Accept-Language":                {},
	"Accept":                         {},
	"Access-Control-Request-Headers": {},
	"Access-Control-Request-Method":  {},
	"Authorization":                  {},
	"Cache-Control":                  {},
	"Connection":                     {},
	"Content-Length":                 {},
	"Content-Type":                   {},
	"Date":                           {},
	"Dnt":                            {},
	"Expect":                         {},
	"Forwarded":                      {},
	"From":                           {},
	"Host":                           {},
	"If-Match":                       {},
	"If-Modified-Since":              {},
	"If-None-Match":                  {},
	"If-Range":                       {},
	"If-Unmodified-Since":            {},
	"Max-Forwards":                   {},
	"Pragma":                         {},
	"Proxy-Authorization":            {},
	"Range":                          {},
	"TE":                             {},
	"Upgrade":                        {},
	"Via":                            {},
	"Warning":                        {},
	"X-CSRF-Token":                   {},
	"X-Requested-With":               {},
}
