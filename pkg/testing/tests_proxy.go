package testing

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"

	"github.com/goccy/go-yaml"
)

// NucleiTestTemplate is a template for testing nuclei templates
type NucleiTestTemplate struct {
	Requests   []RequestResponsePair `yaml:"requests"`
	TemplateID string                `yaml:"template_id"`
}

type internalRouteDetails struct {
	Method string

	ResponseStatus  int
	ResponseHeaders map[string][]string
	ResponseBody    string
}

// MockServer creates a mock server from the test template
func (n *NucleiTestTemplate) MockServer() (http.HandlerFunc, error) {
	requestPathToMethods := make(map[string][]internalRouteDetails)
	for _, reqResp := range n.Requests {
		parsed, err := types.ParseRawRequest(reqResp.Request)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse request")
		}

		parsedResponse, err := http.ReadResponse(bufio.NewReader(strings.NewReader(reqResp.Response)), nil)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse response")
		}

		data, err := io.ReadAll(parsedResponse.Body)
		if err != nil {
			_ = parsedResponse.Body.Close()
			return nil, err
		}
		_ = parsedResponse.Body.Close()

		if _, ok := requestPathToMethods[parsed.URL.Path]; !ok {
			requestPathToMethods[parsed.URL.Path] = []internalRouteDetails{}
		}

		requestPathToMethods[parsed.URL.Path] = append(requestPathToMethods[parsed.URL.Path], internalRouteDetails{
			Method: parsed.Request.Method,

			ResponseStatus:  parsedResponse.StatusCode,
			ResponseHeaders: parsedResponse.Header,
			ResponseBody:    string(data),
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeDetails, ok := requestPathToMethods[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}

		for _, route := range routeDetails {
			if route.Method != r.Method {
				continue
			}

			for k, v := range route.ResponseHeaders {
				w.Header()[k] = v
			}

			w.WriteHeader(route.ResponseStatus)
			_, _ = w.Write([]byte(route.ResponseBody))
			return
		}
	}), nil
}

// ReadNucleiTestTemplate reads a nuclei test template from a file
func ReadNucleiTestTemplate(path string) (*NucleiTestTemplate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var testTemplate NucleiTestTemplate
	dec := yaml.NewDecoder(file)
	if err := dec.Decode(&testTemplate); err != nil {
		return nil, err
	}
	return &testTemplate, nil
}

// GenerateTestsFromPair generates a test from a pair of request and response
// and a template object
func GenerateTestsFromPair(pair []RequestResponsePair, template *templates.Template, target string) error {
	host := target

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsed, err := url.Parse(target)
		if err == nil {
			host = parsed.Hostname()
		}
	}
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	testTemplate := NucleiTestTemplate{
		TemplateID: template.ID,
	}
	for _, reqResp := range pair {
		testTemplate.Requests = append(testTemplate.Requests, RequestResponsePair{
			Request:  redactUserInput(host, reqResp.Request),
			Response: redactUserInput(host, reqResp.Response),
			Protocol: reqResp.Protocol,
		})
	}

	baseDirectory := filepath.Dir(template.Path)
	filename := filepath.Base(template.Path)

	newFile := fmt.Sprintf("%s.nuclei_test", filename)
	gologger.Info().Msgf("Writing test template=%s and target=%s to %s", template.ID, target, newFile)
	newFilename := filepath.Join(baseDirectory, newFile)

	file, err := os.Create(newFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := yaml.NewEncoder(file, yaml.UseLiteralStyleIfMultiline(true), yaml.UseSingleQuote(true))
	if err := enc.Encode(testTemplate); err != nil {
		return err
	}
	defer enc.Close()
	return nil
}

var (
	urlsRegex = regexp.MustCompile(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`)
	ipRegex   = regexp.MustCompile(`((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}`)
)

const redactedTestDomain = "redacted.nuclei-test.domain"

func redactUserInput(input string, value string) string {
	urlMatches := urlsRegex.FindAllString(value, -1)
	for _, match := range urlMatches {
		parsed, err := url.Parse(match)
		if err == nil {
			parsed.Host = redactedTestDomain
			value = strings.ReplaceAll(value, match, parsed.String())
		}
	}
	ips := ipRegex.FindAllString(value, -1)
	for _, ip := range ips {
		value = strings.ReplaceAll(value, ip, "127.0.0.1")
	}
	return strings.ReplaceAll(value, input, redactedTestDomain)
}
