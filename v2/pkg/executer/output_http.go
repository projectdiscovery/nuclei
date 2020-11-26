package executer

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
)

// writeOutputHTTP writes http output to streams
func (e *HTTPExecuter) writeOutputHTTP(req *requests.HTTPRequest, resp *http.Response, body string, matcher *matchers.Matcher, extractorResults []string, meta map[string]interface{}, reqURL string) {
	var URL string
	if req.RawRequest != nil {
		URL = req.RawRequest.FullURL
	}
	if req.Request != nil {
		URL = req.Request.URL.String()
	}

	if e.jsonOutput {
		output := make(jsonOutput)

		output["matched"] = URL
		if !e.noMeta {
			output["template"] = e.template.ID
			output["type"] = "http"
			output["host"] = reqURL
			if len(meta) > 0 {
				output["meta"] = meta
			}
			for k, v := range e.template.Info {
				output[k] = v
			}
			if matcher != nil && len(matcher.Name) > 0 {
				output["matcher_name"] = matcher.Name
			}
			if len(extractorResults) > 0 {
				output["extracted_results"] = extractorResults
			}

			// TODO: URL should be an argument
			if e.jsonRequest {
				dumpedRequest, err := requests.Dump(req, URL)
				if err != nil {
					gologger.Warningf("could not dump request: %s\n", err)
				} else {
					output["request"] = string(dumpedRequest)
				}

				dumpedResponse, err := httputil.DumpResponse(resp, false)
				if err != nil {
					gologger.Warningf("could not dump response: %s\n", err)
				} else {
					output["response"] = string(dumpedResponse) + body
				}
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
		builder.WriteString(colorizer.Colorizer.BrightBlue("http").String())
		builder.WriteString("] ")

		if e.template.Info["severity"] != "" {
			builder.WriteString("[")
			builder.WriteString(colorizer.GetColorizedSeverity(e.template.Info["severity"]))
			builder.WriteString("] ")
		}
	}
	builder.WriteString(URL)

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

	// write meta if any
	if len(req.Meta) > 0 && !e.noMeta {
		builder.WriteString(" [")

		var metas []string
		for name, value := range req.Meta {
			metas = append(metas, colorizer.Colorizer.BrightYellow(name).Bold().String()+"="+colorizer.Colorizer.BrightYellow(fmt.Sprint(value)).String())
		}

		builder.WriteString(strings.Join(metas, ","))
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
