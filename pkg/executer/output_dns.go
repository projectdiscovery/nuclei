package executer

import (
	"strings"

	"github.com/miekg/dns"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
)

// writeOutputDNS writes dns output to streams
// nolint:interfacer // dns.Msg is out of current scope
func (e *DNSExecuter) writeOutputDNS(domain string, req, resp *dns.Msg, matcher *matchers.Matcher, extractorResults []string) {
	if e.jsonOutput {
		output := jsonOutput{
			Template:    e.template.ID,
			Type:        "dns",
			Matched:     domain,
			Name:        e.template.Info.Name,
			Severity:    e.template.Info.Severity,
			Author:      e.template.Info.Author,
			Description: e.template.Info.Description,
		}

		if matcher != nil && len(matcher.Name) > 0 {
			output.MatcherName = matcher.Name
		}

		if len(extractorResults) > 0 {
			output.ExtractedResults = extractorResults
		}

		if e.jsonRequest {
			output.Request = req.String()
			output.Response = resp.String()
		}

		data, err := jsoniter.Marshal(output)
		if err != nil {
			gologger.Warningf("Could not marshal json output: %s\n", err)
		}

		gologger.Silentf("%s", string(data))

		if e.writer != nil {
			e.outputMutex.Lock()
			_, err := e.writer.Write(data)

			if err != nil {
				e.outputMutex.Unlock()
				gologger.Errorf("Could not write output data: %s\n", err)

				return
			}

			_, err = e.writer.WriteRune('\n')

			if err != nil {
				e.outputMutex.Unlock()
				gologger.Errorf("Could not write output data: %s\n", err)

				return
			}
			e.outputMutex.Unlock()
		}

		return
	}

	builder := &strings.Builder{}
	colorizer := e.colorizer

	builder.WriteRune('[')
	builder.WriteString(colorizer.BrightGreen(e.template.ID).String())

	if matcher != nil && len(matcher.Name) > 0 {
		builder.WriteString(":")
		builder.WriteString(colorizer.BrightGreen(matcher.Name).Bold().String())
	}

	builder.WriteString("] [")
	builder.WriteString(colorizer.BrightBlue("dns").String())
	builder.WriteString("] ")
	builder.WriteString(domain)

	// If any extractors, write the results
	if len(extractorResults) > 0 {
		builder.WriteString(" [")

		for i, result := range extractorResults {
			builder.WriteString(colorizer.BrightCyan(result).String())

			if i != len(extractorResults)-1 {
				builder.WriteRune(',')
			}
		}

		builder.WriteString("]")
	}

	builder.WriteRune('\n')

	// Write output to screen as well as any output file
	message := builder.String()
	gologger.Silentf("%s", message)

	if e.writer != nil {
		e.outputMutex.Lock()
		if e.coloredOutput {
			message = e.decolorizer.ReplaceAllString(message, "")
		}

		_, err := e.writer.WriteString(message)

		if err != nil {
			e.outputMutex.Unlock()
			gologger.Errorf("Could not write output data: %s\n", err)

			return
		}
		e.outputMutex.Unlock()
	}
}
