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
		output := make(jsonOutput)
		output["matched"] = domain

		if !e.noMeta {
			output["template"] = e.template.ID
			output["type"] = "dns"
			output["host"] = domain
			for k, v := range e.template.Info {
				output[k] = v
			}
			if matcher != nil && len(matcher.Name) > 0 {
				output["matcher_name"] = matcher.Name
			}
			if len(extractorResults) > 0 {
				output["extracted_results"] = extractorResults
			}
			if e.jsonRequest {
				output["request"] = req.String()
				output["response"] = resp.String()
			}
		}

		data, err := jsoniter.Marshal(output)
		if err != nil {
			gologger.Warningf("Could not marshal json output: %s\n", err)
		}
		gologger.Silentf("%s", string(data))
		if e.writer != nil {
			if err := e.writer.Write(data); err != nil {
				gologger.Errorf("Could not write output data: %s\n", err)
				return
			}
		}
		return
	}

	builder := &strings.Builder{}
	colorizer := e.colorizer

	if !e.noMeta {
		builder.WriteRune('[')
		builder.WriteString(colorizer.Colorizer.BrightGreen(e.template.ID).String())

		if matcher != nil && len(matcher.Name) > 0 {
			builder.WriteString(":")
			builder.WriteString(colorizer.Colorizer.BrightGreen(matcher.Name).Bold().String())
		}

		builder.WriteString("] [")
		builder.WriteString(colorizer.Colorizer.BrightBlue("dns").String())
		builder.WriteString("] ")

		if e.template.Info["severity"] != "" {
			builder.WriteString("[")
			builder.WriteString(colorizer.GetColorizedSeverity(e.template.Info["severity"]))
			builder.WriteString("] ")
		}
	}
	builder.WriteString(domain)

	// If any extractors, write the results
	if len(extractorResults) > 0 && !e.noMeta {
		builder.WriteString(" [")

		for i, result := range extractorResults {
			builder.WriteString(colorizer.Colorizer.BrightCyan(result).String())

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
		if e.coloredOutput {
			message = e.decolorizer.ReplaceAllString(message, "")
		}

		if err := e.writer.WriteString(message); err != nil {
			gologger.Errorf("Could not write output data: %s\n", err)
			return
		}
	}
}
