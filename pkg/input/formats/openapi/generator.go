package openapi

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/clbanning/mxj/v2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/valyala/fasttemplate"
)

// GenerateRequestsFromSchema generates http requests from an OpenAPI 3.0 document object
func GenerateRequestsFromSchema(schema *openapi3.T, callback formats.RawRequestCallback) {
	for _, serverURL := range schema.Servers {
		pathURL := serverURL.URL

		for path, v := range schema.Paths.Map() {
			ops := v.Operations()

			requestPath := path
			for method, ov := range ops {
				if err := generateRequestsFromOp(method, pathURL, requestPath, ov, false, callback); err != nil {
					gologger.Warning().Msgf("Could not generate requests from op: %s\n", err)
				}
			}
		}
	}
}

// generateRequestsFromOp generates requests from an operation and some other data
// about an OpenAPI Schema Path and Method object.
//
// It also accepts an optional requiredOnly flag which if specified, only returns the fields
// of the structure that are required. If false, all fields are returned.
func generateRequestsFromOp(method, pathURL, requestPath string, op *openapi3.Operation, requiredOnly bool, callback formats.RawRequestCallback) error {
	req, err := http.NewRequest(method, pathURL+requestPath, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	query := url.Values{}
	for _, parameter := range op.Parameters {
		value := parameter.Value

		example, err := generateExampleFromSchema(value.Schema.Value)
		if err != nil {
			continue
		}
		if requiredOnly && !value.Required {
			continue // Skip this parameter if it is not required and we want only required ones
		}

		switch value.In {
		case "query":
			query.Set(value.Name, types.ToString(example))
		case "header":
			req.Header.Set(value.Name, types.ToString(example))
		case "path":
			requestPath = fasttemplate.ExecuteStringStd(requestPath, "{", "}", map[string]interface{}{
				value.Name: types.ToString(example),
			})
		case "cookie":
			req.AddCookie(&http.Cookie{Name: value.Name, Value: types.ToString(example)})
		}
	}
	req.URL.RawQuery = query.Encode()
	req.URL.Path = requestPath

	if op.RequestBody != nil {
		for content, value := range op.RequestBody.Value.Content {
			cloned := req.Clone(req.Context())

			example, err := generateExampleFromSchema(value.Schema.Value)
			if err != nil {
				continue
			}

			var body string
			switch content {
			case "application/json":
				if marshalled, err := json.Marshal(example); err == nil {
					body = string(marshalled)
					cloned.Body = io.NopCloser(bytes.NewReader(marshalled))
					cloned.ContentLength = int64(len(marshalled))
					cloned.Header.Set("Content-Type", "application/json")
				}
			case "application/xml":
				exampleVal := mxj.Map(example.(map[string]interface{}))

				if marshalled, err := exampleVal.Xml(); err == nil {
					body = string(marshalled)
					cloned.Body = io.NopCloser(bytes.NewReader(marshalled))
					cloned.ContentLength = int64(len(marshalled))
					cloned.Header.Set("Content-Type", "application/xml")
				} else {
					gologger.Warning().Msgf("could not encode xml")
				}
			case "application/x-www-form-urlencoded":
				if values, ok := example.(map[string]interface{}); ok {
					cloned.Form = url.Values{}
					for k, v := range values {
						cloned.Form.Set(k, types.ToString(v))
					}
					encoded := cloned.Form.Encode()
					cloned.ContentLength = int64(len(encoded))
					body = encoded
					cloned.Body = io.NopCloser(strings.NewReader(encoded))
					cloned.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			case "multipart/form-data":
				if values, ok := example.(map[string]interface{}); ok {
					buffer := &bytes.Buffer{}
					multipartWriter := multipart.NewWriter(buffer)
					for k, v := range values {
						// This is a file if format is binary, otherwise field
						if property, ok := value.Schema.Value.Properties[k]; ok && property.Value.Format == "binary" {
							if writer, err := multipartWriter.CreateFormFile(k, k); err == nil {
								_, _ = writer.Write([]byte(types.ToString(v)))
							}
						} else {
							_ = multipartWriter.WriteField(k, types.ToString(v))
						}
					}
					multipartWriter.Close()
					body = buffer.String()
					cloned.Body = io.NopCloser(buffer)
					cloned.ContentLength = int64(len(buffer.Bytes()))
					cloned.Header.Set("Content-Type", multipartWriter.FormDataContentType())
				}
			case "text/plain":
				str := types.ToString(example)
				body = str
				cloned.Body = io.NopCloser(strings.NewReader(str))
				cloned.ContentLength = int64(len(str))
				cloned.Header.Set("Content-Type", "text/plain")
			default:
				// LOG:	return errors.New("no correct content type found for body")
				continue
			}

			dumped, err := httputil.DumpRequestOut(cloned, true)
			if err != nil {
				return errors.Wrap(err, "could not dump request")
			}

			callback(&formats.RawRequest{
				Method:  cloned.Method,
				URL:     cloned.URL.String(),
				Headers: cloned.Header,
				Body:    body,
				Raw:     string(dumped),
			})
			continue
		}
	}
	if op.RequestBody != nil {
		return nil
	}

	dumped, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return errors.Wrap(err, "could not dump request")
	}

	callback(&formats.RawRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header,
		Raw:     string(dumped),
	})

	return nil
}
