package executer

import (
	"net/http"
	"net/http/httputil"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
)

// writeOutputHTTP writes http output to streams
func (e *HTTPExecuter) writeOutputHTTP(req *requests.HTTPRequest, resp *http.Response, body string, matcher *matchers.Matcher, extractorResults []string) {
	URL := req.Request.URL.String()

	if e.jsonOutput {
		output := jsonOutput{
			Template:    e.template.ID,
			Type:        "http",
			Matched:     URL,
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
			dumpedRequest, err := httputil.DumpRequest(req.Request.Request, true)
			if err != nil {
				gologger.Warningf("could not dump request: %s\n", err)
			} else {
				output.Request = string(dumpedRequest)
			}

			dumpedResponse, err := httputil.DumpResponse(resp, false)

			if err != nil {
				gologger.Warningf("could not dump response: %s\n", err)
			} else {
				output.Response = string(dumpedResponse) + body
			}
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
	builder.WriteString(colorizer.BrightBlue("http").String())
	builder.WriteString("] ")

	// Escape the URL by replacing all % with %%
	escapedURL := strings.ReplaceAll(URL, "%", "%%")
	builder.WriteString(escapedURL)

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

	// write meta if any
	if len(req.Meta) > 0 {
		builder.WriteString(" [")

		var metas []string

		for name, value := range req.Meta {
			metas = append(metas, colorizer.BrightYellow(name).Bold().String()+"="+colorizer.BrightYellow(value.(string)).String())
		}

		builder.WriteString(strings.Join(metas, ","))
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
