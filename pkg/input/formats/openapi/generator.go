package openapi

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/clbanning/mxj/v2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	httpTypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/projectdiscovery/utils/generic"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/valyala/fasttemplate"
)

const (
	globalAuth                 = "globalAuth"
	DEFAULT_HTTP_SCHEME_HEADER = "Authorization"
)

// GenerateRequestsFromSchema generates http requests from an OpenAPI 3.0 document object
func GenerateRequestsFromSchema(schema *openapi3.T, opts formats.InputFormatOptions, callback formats.ParseReqRespCallback) error {
	if len(schema.Servers) == 0 {
		return errors.New("no servers found in openapi schema")
	}

	// new set of globalParams obtained from security schemes
	globalParams := openapi3.NewParameters()

	if len(schema.Security) > 0 {
		params, err := GetGlobalParamsForSecurityRequirement(schema, &schema.Security)
		if err != nil {
			return err
		}
		globalParams = append(globalParams, params...)
	}

	// validate global param requirements
	for _, param := range globalParams {
		if val, ok := opts.Variables[param.Value.Name]; ok {
			param.Value.Example = val
		} else {
			// if missing check for validation
			if opts.SkipFormatValidation {
				gologger.Verbose().Msgf("openapi: skipping all requests due to missing global auth parameter: %s\n", param.Value.Name)
				return nil
			} else {
				// fatal error
				gologger.Fatal().Msgf("openapi: missing global auth parameter: %s\n", param.Value.Name)
			}
		}
	}

	missingVarMap := make(map[string]struct{})
	optionalVarMap := make(map[string]struct{})
	missingParamValueCallback := func(param *openapi3.Parameter, opts *generateReqOptions) {
		if !param.Required {
			optionalVarMap[param.Name] = struct{}{}
			return
		}
		missingVarMap[param.Name] = struct{}{}
	}

	for _, serverURL := range schema.Servers {
		pathURL := serverURL.URL
		// Split the server URL into baseURL and serverPath
		u, err := url.Parse(pathURL)
		if err != nil {
			return errors.Wrap(err, "could not parse server url")
		}
		baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		serverPath := u.Path

		for path, v := range schema.Paths.Map() {
			// a path item can have parameters
			ops := v.Operations()
			requestPath := path
			if serverPath != "" {
				requestPath = serverPath + path
			}
			for method, ov := range ops {
				if err := generateRequestsFromOp(&generateReqOptions{
					requiredOnly:              opts.RequiredOnly,
					method:                    method,
					pathURL:                   baseURL,
					requestPath:               requestPath,
					op:                        ov,
					schema:                    schema,
					globalParams:              globalParams,
					reqParams:                 v.Parameters,
					opts:                      opts,
					callback:                  callback,
					missingParamValueCallback: missingParamValueCallback,
				}); err != nil {
					gologger.Warning().Msgf("Could not generate requests from op: %s\n", err)
				}
			}
		}
	}

	if len(missingVarMap) > 0 && !opts.SkipFormatValidation {
		gologger.Error().Msgf("openapi: Found %d missing parameters, use -skip-format-validation flag to skip requests or update missing parameters generated in %s file,you can also specify these vars using -var flag in (key=value) format\n", len(missingVarMap), formats.DefaultVarDumpFileName)
		gologger.Verbose().Msgf("openapi: missing params: %+v", mapsutil.GetSortedKeys(missingVarMap))
		if config.CurrentAppMode == config.AppModeCLI {
			// generate var dump file
			vars := &formats.OpenAPIParamsCfgFile{}
			for k := range missingVarMap {
				vars.Var = append(vars.Var, k+"=")
			}
			vars.OptionalVars = mapsutil.GetSortedKeys(optionalVarMap)
			if err := formats.WriteOpenAPIVarDumpFile(vars); err != nil {
				gologger.Error().Msgf("openapi: could not write params file: %s\n", err)
			}
			// exit with status code 1
			os.Exit(1)
		}
	}

	return nil
}

type generateReqOptions struct {
	// requiredOnly specifies whether to generate only required fields
	requiredOnly bool
	// method is the http method to use
	method string
	// pathURL is the base url to use
	pathURL string
	// requestPath is the path to use
	requestPath string
	// schema is the openapi schema to use
	schema *openapi3.T
	// op is the operation to use
	op *openapi3.Operation
	// post request generation callback
	callback formats.ParseReqRespCallback

	// global parameters
	globalParams openapi3.Parameters
	// requestparams map
	reqParams openapi3.Parameters
	// global var map
	opts formats.InputFormatOptions
	// missingVar Callback
	missingParamValueCallback func(param *openapi3.Parameter, opts *generateReqOptions)
}

// generateRequestsFromOp generates requests from an operation and some other data
// about an OpenAPI Schema Path and Method object.
//
// It also accepts an optional requiredOnly flag which if specified, only returns the fields
// of the structure that are required. If false, all fields are returned.
func generateRequestsFromOp(opts *generateReqOptions) error {
	req, err := http.NewRequest(opts.method, opts.pathURL+opts.requestPath, nil)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}

	reqParams := opts.reqParams
	if reqParams == nil {
		reqParams = openapi3.NewParameters()
	}
	// add existing req params
	reqParams = append(reqParams, opts.op.Parameters...)
	// check for endpoint specific auth
	if opts.op.Security != nil {
		params, err := GetGlobalParamsForSecurityRequirement(opts.schema, opts.op.Security)
		if err != nil {
			return err
		}
		reqParams = append(reqParams, params...)
	} else {
		reqParams = append(reqParams, opts.globalParams...)
	}

	query := url.Values{}
	for _, parameter := range reqParams {
		value := parameter.Value

		if value.Schema == nil || value.Schema.Value == nil {
			continue
		}

		// paramValue or default value to use
		var paramValue interface{}

		// accept override from global variables
		if val, ok := opts.opts.Variables[value.Name]; ok {
			paramValue = val
		} else if value.Schema.Value.Default != nil {
			paramValue = value.Schema.Value.Default
		} else if value.Schema.Value.Example != nil {
			paramValue = value.Schema.Value.Example
		} else if len(value.Schema.Value.Enum) > 0 {
			paramValue = value.Schema.Value.Enum[0]
		} else {
			if !opts.opts.SkipFormatValidation {
				if opts.missingParamValueCallback != nil {
					opts.missingParamValueCallback(value, opts)
				}
				// skip request if param in path else skip this param only
				if value.Required {
					// gologger.Verbose().Msgf("skipping request [%s] %s due to missing value (%v)\n", opts.method, opts.requestPath, value.Name)
					return nil
				} else {
					// if it is in path then remove it from path
					opts.requestPath = strings.Replace(opts.requestPath, fmt.Sprintf("{%s}", value.Name), "", -1)
					if !opts.opts.RequiredOnly {
						gologger.Verbose().Msgf("openapi: skipping optional param (%s) in (%v) in request [%s] %s due to missing value (%v)\n", value.Name, value.In, opts.method, opts.requestPath, value.Name)
					}
					continue
				}
			}
			exampleX, err := generateExampleFromSchema(value.Schema.Value)
			if err != nil {
				// when failed to generate example
				// skip request if param in path else skip this param only
				if value.Required {
					gologger.Verbose().Msgf("openapi: skipping request [%s] %s due to missing value (%v)\n", opts.method, opts.requestPath, value.Name)
					return nil
				} else {
					// if it is in path then remove it from path
					opts.requestPath = strings.Replace(opts.requestPath, fmt.Sprintf("{%s}", value.Name), "", -1)
					if !opts.opts.RequiredOnly {
						gologger.Verbose().Msgf("openapi: skipping optional param (%s) in (%v) in request [%s] %s due to missing value (%v)\n", value.Name, value.In, opts.method, opts.requestPath, value.Name)
					}
					continue
				}
			}
			paramValue = exampleX
		}
		if opts.requiredOnly && !value.Required {
			// remove them from path if any
			opts.requestPath = strings.Replace(opts.requestPath, fmt.Sprintf("{%s}", value.Name), "", -1)
			continue // Skip this parameter if it is not required and we want only required ones
		}

		switch value.In {
		case "query":
			query.Set(value.Name, types.ToString(paramValue))
		case "header":
			req.Header.Set(value.Name, types.ToString(paramValue))
		case "path":
			opts.requestPath = fasttemplate.ExecuteStringStd(opts.requestPath, "{", "}", map[string]interface{}{
				value.Name: types.ToString(paramValue),
			})
		case "cookie":
			req.AddCookie(&http.Cookie{Name: value.Name, Value: types.ToString(paramValue)})
		}
	}
	req.URL.RawQuery = query.Encode()
	req.URL.Path = opts.requestPath

	if opts.op.RequestBody != nil {
		for content, value := range opts.op.RequestBody.Value.Content {
			cloned := req.Clone(req.Context())

			example, err := generateExampleFromSchema(value.Schema.Value)
			if err != nil {
				continue
			}

			// var body string
			switch content {
			case "application/json":
				if marshalled, err := json.Marshal(example); err == nil {
					// body = string(marshalled)
					cloned.Body = io.NopCloser(bytes.NewReader(marshalled))
					cloned.ContentLength = int64(len(marshalled))
					cloned.Header.Set("Content-Type", "application/json")
				}
			case "application/xml":
				exampleVal := mxj.Map(example.(map[string]interface{}))

				if marshalled, err := exampleVal.Xml(); err == nil {
					// body = string(marshalled)
					cloned.Body = io.NopCloser(bytes.NewReader(marshalled))
					cloned.ContentLength = int64(len(marshalled))
					cloned.Header.Set("Content-Type", "application/xml")
				} else {
					gologger.Warning().Msgf("openapi: could not encode xml")
				}
			case "application/x-www-form-urlencoded":
				if values, ok := example.(map[string]interface{}); ok {
					cloned.Form = url.Values{}
					for k, v := range values {
						cloned.Form.Set(k, types.ToString(v))
					}
					encoded := cloned.Form.Encode()
					cloned.ContentLength = int64(len(encoded))
					// body = encoded
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
					// body = buffer.String()
					cloned.Body = io.NopCloser(buffer)
					cloned.ContentLength = int64(len(buffer.Bytes()))
					cloned.Header.Set("Content-Type", multipartWriter.FormDataContentType())
				}
			case "text/plain":
				str := types.ToString(example)
				// body = str
				cloned.Body = io.NopCloser(strings.NewReader(str))
				cloned.ContentLength = int64(len(str))
				cloned.Header.Set("Content-Type", "text/plain")
			case "application/octet-stream":
				str := types.ToString(example)
				if str == "" {
					// use two strings
					str = "string1\nstring2"
				}
				if value.Schema != nil && generic.EqualsAny(value.Schema.Value.Format, "bindary", "byte") {
					cloned.Body = io.NopCloser(bytes.NewReader([]byte(str)))
					cloned.ContentLength = int64(len(str))
					cloned.Header.Set("Content-Type", "application/octet-stream")
				} else {
					// use string placeholder
					cloned.Body = io.NopCloser(strings.NewReader(str))
					cloned.ContentLength = int64(len(str))
					cloned.Header.Set("Content-Type", "text/plain")
				}
			default:
				gologger.Verbose().Msgf("openapi: no correct content type found for body: %s\n", content)
				// LOG:	return errors.New("no correct content type found for body")
				continue
			}

			dumped, err := httputil.DumpRequestOut(cloned, true)
			if err != nil {
				return errors.Wrap(err, "could not dump request")
			}

			rr, err := httpTypes.ParseRawRequestWithURL(string(dumped), cloned.URL.String())
			if err != nil {
				return errors.Wrap(err, "could not parse raw request")
			}
			opts.callback(rr)
			continue
		}
	}
	if opts.op.RequestBody != nil {
		return nil
	}

	dumped, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return errors.Wrap(err, "could not dump request")
	}

	rr, err := httpTypes.ParseRawRequestWithURL(string(dumped), req.URL.String())
	if err != nil {
		return errors.Wrap(err, "could not parse raw request")
	}
	opts.callback(rr)
	return nil
}

// GetGlobalParamsForSecurityRequirement returns the global parameters for a security requirement
func GetGlobalParamsForSecurityRequirement(schema *openapi3.T, requirement *openapi3.SecurityRequirements) ([]*openapi3.ParameterRef, error) {
	globalParams := openapi3.NewParameters()
	if len(schema.Components.SecuritySchemes) == 0 {
		return nil, errorutil.NewWithTag("openapi", "security requirements (%+v) without any security schemes found in openapi file", schema.Security)
	}
	found := false
	// this api is protected for each security scheme pull its corresponding scheme
schemaLabel:
	for _, security := range *requirement {
		for name := range security {
			if scheme, ok := schema.Components.SecuritySchemes[name]; ok {
				found = true
				param, err := GenerateParameterFromSecurityScheme(scheme)
				if err != nil {
					return nil, err

				}
				globalParams = append(globalParams, &openapi3.ParameterRef{Value: param})
				continue schemaLabel
			}
		}
		if !found && len(security) > 1 {
			// if this is case then both security schemes are required
			return nil, errorutil.NewWithTag("openapi", "security requirement (%+v) not found in openapi file", security)
		}
	}
	if !found {
		return nil, errorutil.NewWithTag("openapi", "security requirement (%+v) not found in openapi file", requirement)
	}

	return globalParams, nil
}

// GenerateParameterFromSecurityScheme generates an example from a schema object
func GenerateParameterFromSecurityScheme(scheme *openapi3.SecuritySchemeRef) (*openapi3.Parameter, error) {
	if !generic.EqualsAny(scheme.Value.Type, "http", "apiKey") {
		return nil, errorutil.NewWithTag("openapi", "unsupported security scheme type (%s) found in openapi file", scheme.Value.Type)
	}
	if scheme.Value.Type == "http" {
		// check scheme
		if !generic.EqualsAny(scheme.Value.Scheme, "basic", "bearer") {
			return nil, errorutil.NewWithTag("openapi", "unsupported security scheme (%s) found in openapi file", scheme.Value.Scheme)
		}
		// HTTP authentication schemes basic or bearer use the Authorization header
		headerName := scheme.Value.Name
		if headerName == "" {
			headerName = DEFAULT_HTTP_SCHEME_HEADER
		}
		// create parameters using the scheme
		switch scheme.Value.Scheme {
		case "basic":
			h := openapi3.NewHeaderParameter(headerName)
			h.Required = true
			h.Description = globalAuth // differentiator for normal variables and global auth
			return h, nil
		case "bearer":
			h := openapi3.NewHeaderParameter(headerName)
			h.Required = true
			h.Description = globalAuth // differentiator for normal variables and global auth
			return h, nil
		}

	}
	if scheme.Value.Type == "apiKey" {
		// validate name and in
		if scheme.Value.Name == "" {
			return nil, errorutil.NewWithTag("openapi", "security scheme (%s) name is empty", scheme.Value.Type)
		}
		if !generic.EqualsAny(scheme.Value.In, "query", "header", "cookie") {
			return nil, errorutil.NewWithTag("openapi", "unsupported security scheme (%s) in (%s) found in openapi file", scheme.Value.Type, scheme.Value.In)
		}
		// create parameters using the scheme
		switch scheme.Value.In {
		case "query":
			q := openapi3.NewQueryParameter(scheme.Value.Name)
			q.Required = true
			q.Description = globalAuth // differentiator for normal variables and global auth
			return q, nil
		case "header":
			h := openapi3.NewHeaderParameter(scheme.Value.Name)
			h.Required = true
			h.Description = globalAuth // differentiator for normal variables and global auth
			return h, nil
		case "cookie":
			c := openapi3.NewCookieParameter(scheme.Value.Name)
			c.Required = true
			c.Description = globalAuth // differentiator for normal variables and global auth
			return c, nil
		}
	}
	return nil, errorutil.NewWithTag("openapi", "unsupported security scheme type (%s) found in openapi file", scheme.Value.Type)
}
