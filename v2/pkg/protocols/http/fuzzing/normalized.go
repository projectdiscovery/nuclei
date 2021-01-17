package fuzzing

import (
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/clbanning/mxj/v2"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

// NormalizedRequest is a structure created from a given request input.
//
// A normalized request represents all the attributes of the request
// and allows modification as well as iteration on the various parts of the
// request structure.
type NormalizedRequest struct {
	// Host contains the host along with port if any.
	Host string
	// Scheme contains the scheme of the request.
	Scheme string
	// Path is the path to send the request to
	Path string
	// Method is the HTTP method with which to send the request
	Method string
	// MultipartBody is a multipart body for the request.
	MultipartBody map[string]NormalizedMultipartField
	// FormData is the urlencoded post body for the request
	FormData map[string][]string
	// JSONData contains the unmarshalled JSON data for the request
	JSONData map[string]interface{}
	// XMLData contains the unmarshalled XML data for the request
	XMLData map[string]interface{}
	// Body contains the body for the request if any.
	Body string
	// QueryValues contains the query parameter values for the request if any.
	QueryValues map[string][]string
	// Headers contains the map of headers for the request.
	Headers http.Header
	// Cookies contains all the cookies for the request.
	Cookies map[string]string
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
func NormalizeRequest(req *http.Request) (*NormalizedRequest, error) {
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
		if err := normalized.parseBody(req, mediaType, params); err != nil {
			return nil, errors.Wrap(err, "could not parse body")
		}
	}

	cookies := req.Header.Values("Cookie")
	if len(cookies) == 0 {
		return normalized, nil
	}

	normalized.Cookies = make(map[string]string)
	for _, cookie := range cookies {
		parts := strings.Split(cookie, " ")
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			normalized.Cookies[kv[0]] = strings.TrimSuffix(kv[1], ";")
		}
	}
	normalized.Headers.Del("Cookie")
	return normalized, nil
}

// parseBody parses various types of http reqeust bodies and fills
// up the normalized structure depending on the content type and value
// of the body.
//
// Currently handled bodies include Multipart, Form URL Encoded, JSON, XML
// and raw body.
func (n *NormalizedRequest) parseBody(req *http.Request, mediaType string, params map[string]string) error {
	if strings.HasPrefix(mediaType, "multipart/") {
		n.MultipartBody = make(map[string]NormalizedMultipartField)

		mr := multipart.NewReader(req.Body, params["boundary"])
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
		if err := req.ParseForm(); err != nil {
			return errors.Wrap(err, "could not parse form data")
		}
		n.FormData = make(map[string][]string)
		for k, v := range req.Form {
			n.FormData[k] = v
		}
		n.Headers.Del("Content-Type")
		return nil
	}
	if strings.HasPrefix(mediaType, "application/json") {
		if err := jsoniter.NewDecoder(req.Body).Decode(&n.JSONData); err != nil {
			return errors.Wrap(err, "could not decode json body")
		}
		n.Headers.Del("Content-Type")
		return nil
	}
	if strings.HasPrefix(mediaType, "text/xml") {
		mv, err := mxj.NewMapXmlReader(req.Body)
		if err != nil {
			return errors.Wrap(err, "could not decode xml body")
		}
		n.XMLData = mv
		n.Headers.Del("Content-Type")
		return nil
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	n.Body = string(body)
	return nil
}
