package fuzzing

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/clbanning/mxj/v2"
	jsoniter "github.com/json-iterator/go"
	"github.com/morikuni/accessor"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/valyala/fasttemplate"
)

// AnalyzerOptions contains configuration options for the injection
// point analyzer.
type AnalyzerOptions struct {
	// Append appends a value to the value for a key found during analysis.
	//
	// Append is most commonly used to preserve old data and add payloads at the
	// end of the old data marker.
	Append []string `yaml:"append"`

	// Replace replaces a value for a key found during analysis.
	//
	// Replace is most commonly used to replace old data with completely new data.
	Replace []string `yaml:"replace"`

	// BodyTemplate is an optional field describing a template body
	// that will be sent for a specific body-type.
	BodyTemplate string `yaml:"body-template"`

	// BodyType is the type of body to format with body template.
	//   1. xml
	//   2. json
	//   3. form
	BodyType string `yaml:"body-type"`

	// MaxDepth is the maximum number of document nesting to fuzz for.
	MaxDepth int `yaml:"max-depth"`

	// Parts is the list of parts to fuzz for the request.
	//
	// Valid value mappings are -
	//   default =>  everything except the path and cookies will be fuzzed. (optimal)
	//    If no values are provided, parts are assumed to be default by the engine.
	//    Providing any other part overrides the default part and enables honouring of those
	//    other part values.
	//
	//   path, cookies, body, query-values, headers => self explanatory.
	//
	//   all => All enables fuzzing of all request parts.
	Parts []string `yaml:"parts"`

	// PartsConfig contains a map of configuration for various
	// analysis parts. This configuration will be used to customize
	// the process of fuzzing these part values.
	//
	// Keys are the values provided by the parts field of the configuration.
	// Values contains configuration options for choosing the said part.
	PartsConfig map[string][]*AnalyzerPartsConfig `yaml:"parts-config"`
}

// AnalyzeRequest analyzes a normalized request with an analyzer
// configuration and returns all the points where input can be tampered
// or supplied to detect web vulnerabilities.
//
// Parts are fuzzed on the basis of key value pairs. Various parts of the request
// form iterators which can be then iterated on the basis of key-value pairs.
// First validation is performed by the parts-config value of configuration to
// choose whether this field can be fuzzed or not. If the part can be fuzzed, testing
// is finally performed for the request.
func AnalyzeRequest(req *NormalizedRequest, options *AnalyzerOptions, callback func(*http.Request) bool) error {
	var reqBody io.ReadCloser
	var contentType string
	var contentLength int
	var err error

	transforms := CreateTransform(req, options)
	for _, transform := range transforms {
		gologger.Debug().Msgf("Transformed input with [%s] %s => %s\n", transform.Part, transform.Key, transform.Value)
	}
	for _, transform := range transforms {
		// If we have multipart body, add it to the request.
		if len(req.MultipartBody) > 0 {
			reqBody, contentLength, contentType, err = options.analyzeMultipartBody(req, transform)
		}
		// If we have form data body, add it to the request.
		if len(req.FormData) > 0 {
			reqBody, contentLength, contentType, err = options.analyzeFormBody(req, transform)
		}
		// If we have JSON data body, add it to the request.
		if req.JSONData != nil {
			reqBody, contentLength, contentType, err = options.analyzeJSONBody(req, transform)
		}
		// If we have XML data body, add it to the request.
		if len(req.XMLData) > 0 {
			reqBody, contentLength, contentType, err = options.analyzeXMLBody(req, transform)
		}
		if req.Body != "" {
			reqBody = ioutil.NopCloser(strings.NewReader(req.Body))
			contentLength = len(req.Body)
			contentType = req.Headers.Get("Content-Type")
		}
		if err != nil {
			gologger.Warning().Msgf("Could not create request for fuzzing: %s\n", err)
			continue
		}
		if contentType == "" {
			contentType = req.Headers.Get("Content-Type")
		}

		builder := &strings.Builder{}
		builder.WriteString(req.Scheme)
		builder.WriteString("://")
		builder.WriteString(req.Host)

		if strings.EqualFold(transform.Part, "path") {
			builder.WriteString(transform.Value)
		} else {
			builder.WriteString(req.Path)
		}
		newRequest, err := http.NewRequest(req.Method, builder.String(), reqBody)
		if err != nil {
			return err
		}
		query := &url.Values{}
		for k, v := range req.QueryValues {
			for _, value := range v {
				query.Add(k, value)
			}
			if strings.EqualFold(transform.Part, "query-values") && strings.EqualFold(k, transform.Key) {
				query.Set(k, transform.Value)
			}
		}
		newRequest.URL.RawQuery = query.Encode()

		for k, v := range req.Headers {
			for _, value := range v {
				newRequest.Header.Add(k, value)
			}
			if strings.EqualFold(transform.Part, "headers") && strings.EqualFold(k, transform.Key) {
				newRequest.Header.Set(k, transform.Value)
			}
		}
		if req.Headers.Get("Content-Length") != "" && contentLength != 0 {
			newRequest.ContentLength = int64(contentLength)
		}
		if contentType != "" {
			newRequest.Header.Set("Content-Type", contentType)
		}

		builder.Reset()
		for k, v := range req.Cookies {
			for _, value := range v {
				builder.WriteString(k)
				builder.WriteString("=")
				if strings.EqualFold(transform.Part, "cookies") && strings.EqualFold(k, transform.Key) {
					builder.WriteString(transform.Value)
				} else {
					builder.WriteString(value)
				}
				builder.WriteString(";")
				builder.WriteString(" ")
			}
		}
		cookieString := strings.TrimSpace(builder.String())
		if cookieString != "" {
			newRequest.Header.Set("Cookie", cookieString)
		}
		newRequest.Header.Del("Connection")
		newRequest.Close = false

		// if user asks for no more requests, break
		if !callback(newRequest) {
			break
		}
	}
	return nil
}

// analyzeMultipartBody analyzes multipart body and also fuzzes if asked.
func (o *AnalyzerOptions) analyzeMultipartBody(req *NormalizedRequest, transform *Transform) (io.ReadCloser, int, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for k, v := range req.MultipartBody {
		var value string
		if strings.EqualFold(transform.Part, "body") {
			if strings.EqualFold(transform.Key, k) {
				value = transform.Value
			} else {
				value = v.Value
			}
		}
		if v.Filename != "" {
			fileWriter, err := writer.CreateFormFile(k, v.Filename)
			if err != nil {
				return nil, 0, "", errors.Wrap(err, "could not write file")
			}
			fileWriter.Write([]byte(value))
		} else {
			if err := writer.WriteField(k, value); err != nil {
				return nil, 0, "", errors.Wrap(err, "could not write field")
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, 0, "", errors.Wrap(err, "could not close multipart writer")
	}
	return ioutil.NopCloser(body), body.Len(), writer.FormDataContentType(), nil
}

// analyzeFormBody analyzes form body and also fuzzes if asked.
func (o *AnalyzerOptions) analyzeFormBody(req *NormalizedRequest, transform *Transform) (io.ReadCloser, int, string, error) {
	data := url.Values{}

	for k, v := range req.FormData {
		for _, value := range v {
			data.Add(k, value)
		}
		if strings.EqualFold(transform.Part, "body") && strings.EqualFold(transform.Key, k) {
			data.Set(k, transform.Value)
		}
	}
	encoded := data.Encode()
	if strings.EqualFold(o.BodyType, "form") {
		encoded = fasttemplate.ExecuteStringStd(o.BodyTemplate, "{{", "}}", map[string]interface{}{"body": encoded})
	}
	return ioutil.NopCloser(strings.NewReader(encoded)), len(encoded), "", nil
}

// analyzeJSONBody analyzes json body and also fuzzes if asked.
func (o *AnalyzerOptions) analyzeJSONBody(req *NormalizedRequest, transform *Transform) (io.ReadCloser, int, string, error) {
	acc, err := accessor.NewAccessor(req.JSONData)
	if err != nil {
		return nil, 0, "", errors.Wrap(err, "could not access json data")
	}

	if strings.EqualFold(transform.Part, "body") {
		path, err := accessor.ParsePath(transform.Key)
		if err != nil {
			return nil, 0, "", errors.Wrap(err, "could not parse fuzzing path")
		}
		if err = acc.Set(path, transform.Value); err != nil {
			return nil, 0, "", errors.Wrap(err, "could not set fuzzing path")
		}
	}
	buffer := &bytes.Buffer{}
	enc := jsoniter.NewEncoder(buffer)
	enc.SetEscapeHTML(false)
	// note: using accessor package requires unwrapping the actual object
	// to be able to see the made modifications.
	if err := enc.Encode(acc.Unwrap()); err != nil {
		return nil, 0, "", errors.Wrap(err, "could not write json data")
	}
	var data io.Reader
	if strings.EqualFold(o.BodyType, "json") {
		data = strings.NewReader(fasttemplate.ExecuteStringStd(o.BodyTemplate, "{{", "}}", map[string]interface{}{"body": buffer.String()}))
	} else {
		data = buffer
	}
	return ioutil.NopCloser(data), buffer.Len(), "", nil
}

// analyzeXMLBody analyzes xml body and also fuzzes if asked.
func (o *AnalyzerOptions) analyzeXMLBody(req *NormalizedRequest, transform *Transform) (io.ReadCloser, int, string, error) {
	acc, err := accessor.NewAccessor(req.XMLData)
	if err != nil {
		return nil, 0, "", errors.Wrap(err, "could not access XML data")
	}

	if strings.EqualFold(transform.Part, "body") {
		path, err := accessor.ParsePath(transform.Key)
		if err != nil {
			return nil, 0, "", errors.Wrap(err, "could not parse fuzzing path")
		}
		if err = acc.Set(path, transform.Value); err != nil {
			return nil, 0, "", errors.Wrap(err, "could not set fuzzing path")
		}
	}
	buffer := &bytes.Buffer{}
	if err := mxj.Map(acc.Unwrap().(map[string]interface{})).XmlWriter(buffer); err != nil {
		return nil, 0, "", errors.Wrap(err, "could not write xml data")
	}
	var data io.Reader
	if strings.EqualFold(o.BodyType, "xml") {
		template := o.BodyTemplate
		if req.XMLPrefix != "" {
			builder := &strings.Builder{}
			builder.WriteString("{{prefix}}")
			builder.WriteString(o.BodyTemplate)
			template = builder.String()
		}
		data = strings.NewReader(fasttemplate.ExecuteStringStd(template, "{{", "}}", map[string]interface{}{"body": buffer.String(), "prefix": req.XMLPrefix}))
	} else {
		data = buffer
	}
	return ioutil.NopCloser(data), buffer.Len(), "", nil
}
