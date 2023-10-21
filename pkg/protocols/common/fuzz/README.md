# Nuclei Fuzzing Layer

Nuclei Fuzzing Lazyer adds support for enhanced HTTP Request fuzzing support in nuclei to allow additional of DAST capabilities to Nuclei. This enhances the existing fuzzing implementation adding more bells and whistles for Blind Web Application Vulnerability scanning.

## Parts

There are a number of components that work together in the fuzzing layer. A detailed description of each along with its examples are provided below.

### Input Formats

The addition of fuzzing functionality enhancements also comes with a lot of additional input formats support which will be utilized to provide input to the fuzzing layer for execution. The following formats are planned to be covered - 

- [ ] JSONL Output
  - [ ] proxify
  - [ ] katana
  - [ ] httpx
- [ ] Burp XML File
- [ ] OpenAPI Definition
- [ ] Swagger Definition
- [ ] Postman Definition
- [ ] HAR File
- [ ] Raw Text Files

### Encoding

Encoding layer implements the `encoding.Encoder` interface which is implemented by different data encoding formats like `Base64`, `URLEncoding`, etc. This is used in turn by the engine to understand the encodings used in various values of the web-app which can assist in fuzzing encoded inputs. It also provides the reverse, re-encoding the data back into the value that can be used to encode inputs, supporting nested encodings as well.

```go
// Encoder is an interface for encoding and decoding data.
type Encoder interface {
	// IsType returns true if the data is of the type
	IsType(data string) bool
	// Name returns the name of the encoder
	Name() string
	// Encode encodes the data into a format
	Encode(data string) string
	// Decode decodes the data from a format
	Decode(data string) (string, error)
}
```

The API is accessible by calling `encoding.Decode` which returns a `Decoded` structure. You can re-encode new values with the same chain of encoders by calling `(*Decoded).Encode(<data>)` with the data you want to encode. Encoding is automatically identified with nesting as well in this implementation.

The following encodings are implemented -

- Base64
- URL Encoding

### DataFormat

DataFormat layer impelements the different data formats that can be used by web applications for fuzzing layer support in Nuclei. Examples are `raw`, `xml`, `multipart`, `json`, `form`, etc.

```go
// DataFormat is an interface for encoding and decoding
type DataFormat interface {
	// IsType returns true if the data is of the type
	IsType(data string) bool
	// Name returns the name of the encoder
	Name() string
	// Encode encodes the data into a format
	Encode(data map[string]interface{}) (string, error)
	// Decode decodes the data from a format
	Decode(input string) (map[string]interface{}, error)
}
```

The API is accessible by calling `dataformat.Decode` which returns a `map[string]interface{}` along with the identified format. The format is automatically identified by using `IsType` method of individual dataformat or they can be explicitly forced by `dataformat.Get` as well. To re-encode, call `dataformat.Encode` method.

The following dataformats are implemented - 

- Raw
- XML
- JSON
- Multipart
- Form

### Component

Component is a part of the HTTP request that can be fuzzed individually. For example - `body`, `cookie`, `header`, `query`, `url`, etc.

```go
// Component is a component for a request
type Component interface {
	// Name returns the name of the component
	Name() string
	// Parse parses the component and returns the
	// parsed component
	Parse(req *retryablehttp.Request) (bool, error)
	// Iterate iterates through the component
	//
	// We cannot iterate normally because there
	// can be multiple nesting. So we need to a do traversal
	// and get keys with values that can be assigned values dynamically.
	// Therefore we flatten the value map and iterate over it.
	//
	// The mutation layer decides how to change the value and then
	// the SetValue method is called to set the final string into
	// the Value. The value container handles arrays, maps, strings etc
	// and then encodes and converts them into final string.
	Iterate(func(key string, value interface{}))
	// SetValue sets a value in the component
	// for a key
	//
	// After calling setValue for mutation, the value must be
	// called again so as to reset the body to its original state.
	SetValue(key string, value string) error
	// Rebuild returns a new request with the
	// component rebuilt
	Rebuild() (*retryablehttp.Request, error)
}
```

The above is the interface implemented by `Component`. A new component can be created with `component.New` method. A list of available components in `component.Components`. 

The below is the list of implemented components - 

- Body
- Query
- URL
- Header
- Cookie

### Analyzers

Analyzers are an additional component added to nuclei to augument the fuzzing capabilities that will be newly added. 

The following analyzers are planned to be added - 

1. `time-delay`
2. `xss-context`
3. `heuristics`

**time-delay** analyzer -

This addition allows `time-delay` analysis by dynamically inserting time into `{{delay}}` placeholder and observing the time duration changes of the request. 

**xss-context** analyzer - 

This addition allows `context-analysis` for detecting Cross Site Scripting attacks by using a HTML + JS parser to identify inputs and detect potential vulnerabilities. 

**heuristics** analyzer - 

Heuristics analyzer allows checking requests for differences by issuing different versions of the request and identifying whether the response can be controlled by the input or a significant enough change occurs. This can be used to detect things like Boolean Based SQLi, etc.
## Configurations

- [ ] Allow configuring parts of request to fuzz
  - [ ] allow subselection also like XML Attribute, XML Parameter, multipart Filename, Contents, etc
- [ ] Allow configuring components of request to fuzz
- [ ] Add optional Anti-CSRF mechanism inspired by zap technique (record pages producing csrf, have allowlist and use it to re-request tokens)
- [ ] Allow ignoring parameters with a regex - 


### Zapproxy default parameters exclusion list - 

- (?i)ASP.NET_SessionId", NameValuePair.TYPE_UNDEFINED
- (?i)ASPSESSIONID.*", NameValuePair.TYPE_UNDEFINED
- (?i)PHPSESSID", NameValuePair.TYPE_UNDEFINED
- (?i)SITESERVER", NameValuePair.TYPE_UNDEFINED
- (?i)sessid", NameValuePair.TYPE_UNDEFINED
- __VIEWSTATE", NameValuePair.TYPE_POST_DATA
- __EVENTVALIDATION", NameValuePair.TYPE_POST_DATA
- __EVENTTARGET", NameValuePair.TYPE_POST_DATA
- __EVENTARGUMENT", NameValuePair.TYPE_POST_DATA
- javax.faces.ViewState", NameValuePair.TYPE_POST_DATA
- (?i)jsessionid", NameValuePair.TYPE_UNDEFINED
- cfid", NameValuePair.TYPE_COOKIE
- cftoken", NameValuePair.TYPE_COOKIE

### CSRF Token parameter names - 

- "anticsrf",
- "CSRFToken",
- "__RequestVerificationToken",
- "csrfmiddlewaretoken",
- "authenticity_token",
- "OWASP_CSRFTOKEN",
- "anoncsrf",
- "csrf_token",
- "_csrf",
- "_csrfSecret",
- "__csrf_magic",
- "CSRF",
- "_token",
- "_csrf_token"

1. Skip irrelevant checks -> SSRF shouldn't be discovered by default on parameters that have non-URL values.

Skip all tests for below parameter names

true	Cookie	Name	Matches regex	aspsessionid.*
true	Cookie	Name	Is	asp.net_sessionid
true	Body parameter	Name	Is	__eventtarget
true	Body parameter	Name	Is	__eventargument
true	Body parameter	Name	Is	__viewstate
true	Body parameter	Name	Is	__eventvalidation
true	Any parameter	Name	Is	jsessionid
true	Cookie	Name	Is	cfid
true	Cookie	Name	Is	cftoken
true	Cookie	Name	Is	PHPSESSID
true	Cookie	Name	Is	session_id
true	XML attribute	Name	Is	version
true	XML attribute	Name	Is	encoding
true	XML attribute	Name	Is	standalone
true	XML attribute	Name	Matches regex	xmlns.*
true	XML attribute	Name	Is	xml:lang
true	XML attribute	Name	Is	lang
true	Cookie	Name	Is	_ga
true	Cookie	Name	Is	_gid
true	Cookie	Name	Is	_gat
true	Cookie	Name	Matches regex	_ga_.*
true	Cookie	Name	Matches regex	_gac_.*
true	Cookie	Name	Matches regex	AWSALB.*

- During fuzzing, record frequently occuring parameters which don't match anything and do not run [future idea].
### Ideas

- Add a disallowed_paths options
- Add disallowed_parameters options
- Allow user full customization during scanning
- Support various authentication methods
