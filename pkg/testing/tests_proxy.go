package testing

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"

	"github.com/goccy/go-yaml"
)

// NucleiTestTemplate is a template for testing nuclei templates
type NucleiTestTemplate struct {
	Requests            []RequestResponsePair `yaml:"requests"`
	TemplateID          string                `yaml:"template_id"`
	IsInteractshMatcher bool                  `yaml:"is_interactsh_matcher,omitempty"`
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
		parsed, err := types.ParseRawRequest(strings.TrimLeft(reqResp.Request, "\r\n"))
		if err != nil {
			return nil, errors.Wrap(err, "could not parse request")
		}

		parsedResponse, err := http.ReadResponse(bufio.NewReader(strings.NewReader(strings.TrimLeft(reqResp.Response, "\r\n"))), nil)
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

			if n.IsInteractshMatcher {
				dumped, _ := httputil.DumpRequest(r, true)
				decoded, _ := url.QueryUnescape(string(dumped))

				for _, url := range extractURLs(decoded) {
					if !isAllowedDomain(url) {
						continue
					}

					go func(url string) {
						if err := doCallbackToInteractsh(url); err != nil {
							gologger.Warning().Msgf("[test-server] Could not send request to interactsh: %s", err)
						}
					}(url)
				}
			}
			for k, v := range route.ResponseHeaders {
				// Ignore certain headers
				if k == "Content-Encoding" {
					continue
				}
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
func GenerateTestsFromPair(pair []RequestResponsePair, template *templates.Template, target string, isInteractshMatcher bool) error {
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
		TemplateID:          template.ID,
		IsInteractshMatcher: isInteractshMatcher,
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

func extractURLs(text string) []string {
	matches := domainRegex.FindAllString(text, -1)

	for i, match := range matches {
		if !strings.HasPrefix(match, "http://") && !strings.HasPrefix(match, "https://") {
			matches[i] = "http://" + match
		}
	}
	return matches
}

var domainRegex = regexp.MustCompile(`(?:https?:\/\/)?[A-Za-z0-9-_\.]+oast\.(?:pro|today|live|site|online|fun|me)`)

func isAllowedDomain(urlString string) bool {
	domainsEnabled := true
	if !domainsEnabled {
		return true
	}

	allowedDomains := []string{"oast.pro", "oast.today", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me"}
	u, err := url.Parse(urlString)
	if err != nil {
		return false
	}
	for _, domain := range allowedDomains {
		if strings.HasSuffix(u.Hostname(), domain) {
			return true
		}
	}
	return false
}

func doCallbackToInteractsh(URL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", URL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	return err
}
