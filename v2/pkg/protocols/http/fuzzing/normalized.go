package fuzzing

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/clbanning/mxj/v2"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/retryablehttp-go"
)

// NormalizedRequest is a structure created from a given request input.
//
// A normalized request represents all the attributes of the request
// and allows modification as well as iteration on the various parts of the
// request structure.
type NormalizedRequest struct {
	// Host contains the host along with port if any.
	Host string `json:"host,omitempty"`
	// Scheme contains the scheme of the request.
	Scheme string `json:"scheme,omitempty"`
	// Path is the path to send the request to
	Path string `json:"path,omitempty"`
	// Method is the HTTP method with which to send the request
	Method string `json:"method,omitempty"`
	// MultipartBody is a multipart body for the request.
	MultipartBody map[string]NormalizedMultipartField `json:"multipart-body,omitempty"`
	// FormData is the urlencoded post body for the request
	FormData map[string][]string `json:"form-body,omitempty"`
	// JSONData contains the unmarshalled JSON data for the request
	JSONData interface{} `json:"json-body,omitempty"`
	// XMLData contains the unmarshalled XML data for the request
	XMLData   mxj.Map `json:"xml-body,omitempty"`
	XMLPrefix string  `json:"xml-prefix,omitempty"`
	// Body contains the body for the request if any.
	Body string `json:"body,omitempty"`
	// QueryValues contains the query parameter values for the request if any.
	QueryValues map[string][]string `json:"query-values,omitempty"`
	// Headers contains the map of headers for the request.
	Headers http.Header `json:"headers,omitempty"`
	// Cookies contains all the cookies for the request.
	Cookies map[string][]string `json:"cookies,omitempty"`
}

// NormalizedMultipartField is the normalized multipart field
type NormalizedMultipartField struct {
	Value    string
	Filename string
}

// MultipartFieldType is the field type of multipart data
type MultipartFieldType int

// NormalizeRequest normalizes a net/http request into an intermediate
// representation which can be iterated upon by the nuclei fuzzing engine.
func NormalizeRequest(req *retryablehttp.Request) (*NormalizedRequest, error) {
	normalized := &NormalizedRequest{
		Host:        req.URL.Host,
		Scheme:      req.URL.Scheme,
		Method:      req.Method,
		Path:        req.URL.Path,
		QueryValues: req.URL.Query(),
		Headers:     req.Header,
	}
	mediaType, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))

	if req.Body != nil {
		body, err := req.BodyBytes()
		if err == nil {
			if err := normalized.parseBody(ioutil.NopCloser(bytes.NewReader(body)), req, mediaType, params); err != nil {
				return nil, errors.Wrap(err, "could not parse body")
			}
		}
	}

	cookies := req.Header.Values("Cookie")
	if len(cookies) == 0 {
		return normalized, nil
	}

	normalized.Cookies = make(map[string][]string)
	for _, cookie := range cookies {
		parts := strings.Split(cookie, " ")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			value := strings.TrimSuffix(kv[1], ";")
			if parts, ok := normalized.Cookies[kv[0]]; !ok {
				normalized.Cookies[kv[0]] = []string{value}
			} else {
				parts = append(parts, value)
			}
		}
	}
	normalized.Headers.Del("Cookie")
	return normalized, nil
}

var elementRegex = regexp.MustCompile(`<[A-Za-z]`)

// parseBody parses various types of http reqeust bodies and fills
// up the normalized structure depending on the content type and value
// of the body.
//
// Currently handled bodies include Multipart, Form URL Encoded, JSON, XML
// and raw body.
func (n *NormalizedRequest) parseBody(body io.ReadCloser, req *retryablehttp.Request, mediaType string, params map[string]string) error {
	if strings.HasPrefix(mediaType, "multipart/") {
		n.MultipartBody = make(map[string]NormalizedMultipartField)

		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				n.Headers.Del("Content-Type")
				return nil
			}
			if err != nil {
				return errors.Wrap(err, "could not parse form data")
			}

			slurp, err := ioutil.ReadAll(p)
			if err != nil {
				return errors.Wrap(err, "could not read form data")
			}
			n.MultipartBody[p.FormName()] = NormalizedMultipartField{
				Value:    string(slurp),
				Filename: p.FileName(),
			}
		}
	}
	if strings.HasPrefix(mediaType, "application/x-www-form-urlencoded") {
		data, err := ioutil.ReadAll(body)
		if err != nil {
			return err
		}
		values, err := url.ParseQuery(string(data))
		if err != nil {
			return err
		}
		n.FormData = make(map[string][]string)
		for k, v := range values {
			n.FormData[k] = v
		}
		return nil
	}
	if strings.HasPrefix(mediaType, "application/json") {
		if err := jsoniter.ConfigCompatibleWithStandardLibrary.NewDecoder(body).Decode(&n.JSONData); err != nil {
			return errors.Wrap(err, "could not decode json body")
		}
		return nil
	}
	if strings.HasPrefix(mediaType, "text/xml") || strings.HasPrefix(mediaType, "application/xml") {
		data, err := ioutil.ReadAll(body)
		if err != nil {
			return err
		}
		loc := elementRegex.FindIndex(data)
		if len(loc) > 0 {
			n.XMLPrefix = string(data[:loc[0]])
		}
		mv, err := mxj.NewMapXmlReader(bytes.NewReader(data))
		if err != nil {
			return errors.Wrap(err, "could not decode xml body")
		}
		n.XMLData = mv
		return nil
	}
	data, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}
	n.Body = string(data)
	return nil
}
