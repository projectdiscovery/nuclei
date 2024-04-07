package testing

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"

	"github.com/goccy/go-yaml"
)

// NucleiTestTemplate is a template for testing nuclei templates
type NucleiTestTemplate struct {
	Requests   []RequestResponsePair `yaml:"requests"`
	TemplateID string                `yaml:"template_id"`
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
