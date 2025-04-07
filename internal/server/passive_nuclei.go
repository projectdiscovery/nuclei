package server

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/offlinehttp"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type PassiveNucleiExecutor struct {
	defaultTemplates   []*templates.Template
	pathBasedTemplates map[string][]*templates.Template
}

func NewPassiveNucleiExecutor(templatesDir string) (*PassiveNucleiExecutor, error) {
	catalog := disk.NewCatalog(templatesDir)

	opts := types.DefaultOptions()
	opts.ExcludeTags = []string{"cve", "lfi", "xss", "rce", "ssrf", "cmdi", "oast", "ssti", "sqli"}
	opts.ExcludedTemplates = []string{
		"http/vulnerabilities/",
		"http/cves",
		"http/cnvd",
		"http/fuzzing",
	}
	opts.ExcludeIds = []string{
		"tech-detect", "fingerprinthub-web-fingerprints", "credentials-disclosure",
		"aws-detect",
	}
	opts.Protocols = templateTypes.ProtocolTypes{templateTypes.HTTPProtocol}

	executorOpts := protocols.ExecutorOptions{
		Options: opts,
		Catalog: catalog,
		Parser:  templates.NewParser(),
	}
	if err := protocolinit.Init(opts); err != nil {
		return nil, err
	}

	store, err := loader.New(loader.NewConfig(opts, catalog, executorOpts))
	if err != nil {
		return nil, err
	}
	store.Load()

	loadedTemplates := store.Templates()
	offlinehttp.RawInputMode = true

	var defaultTemplates []*templates.Template
	pathBasedTemplates := make(map[string][]*templates.Template)

	for _, tpl := range loadedTemplates {
		if len(tpl.RequestsWithHTTP) != 1 {
			continue
		}
		if tpl.SelfContained || tpl.Flow != "" {
			continue
		}
		for _, item := range tpl.RequestsWithHTTP {
			if len(item.Path) == 0 {
				continue
			}
			if err := compileOfflineHTTPRequest(tpl, &executorOpts); err != nil {
				slog.Warn("Error compiling template", slog.String("id", tpl.ID), slog.String("error", err.Error()))
				continue
			}
			for _, path := range item.Path {
				// Default templates are not path based
				if path == "{{BaseURL}}" || path == "{{BaseURL}}/" {
					defaultTemplates = append(defaultTemplates, tpl)
					continue
				}
				pathCleaned := strings.TrimPrefix(path, "{{BaseURL}}")
				pathBasedTemplates[pathCleaned] = append(pathBasedTemplates[pathCleaned], tpl)
			}
		}
	}
	return &PassiveNucleiExecutor{
		defaultTemplates:   defaultTemplates,
		pathBasedTemplates: pathBasedTemplates,
	}, nil
}

func (e *PassiveNucleiExecutor) Execute(ctx context.Context, input, URL string) ([]*output.ResultEvent, error) {
	parsedURL, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}

	var allResults []*output.ResultEvent
	for _, tpl := range e.defaultTemplates {
		results, err := executeTemplate(ctx, tpl, input, parsedURL)
		if err != nil {
			gologger.Warning().Msgf("Error executing template %s: %s\n", tpl.ID, err)
			return nil, err
		}
		allResults = append(allResults, results...)
	}

	templates, ok := e.pathBasedTemplates[parsedURL.Path]
	if !ok || len(templates) == 0 {
		return allResults, nil
	}

	for _, tpl := range templates {
		results, err := executeTemplate(ctx, tpl, input, parsedURL)
		if err != nil {
			gologger.Warning().Msgf("Error executing template %s: %s\n", tpl.ID, err)
			continue
		}
		allResults = append(allResults, results...)
	}
	return allResults, nil
}

func executeTemplate(ctx context.Context, tpl *templates.Template, input string, parsedURL *url.URL) ([]*output.ResultEvent, error) {
	results, err := tpl.Executer.ExecuteWithResults(scan.NewScanContext(ctx, contextargs.NewWithInput(ctx, input)))
	if err != nil {
		return nil, err
	}
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	urlString := parsedURL.String()
	for _, result := range results {
		result.Info = tpl.Info
		result.TemplateID = tpl.ID
		result.TemplatePath = tpl.Path
		result.URL = urlString
		result.Host = parsedURL.Host
		result.Path = parsedURL.Path
		result.Scheme = parsedURL.Scheme
		result.Path = parsedURL.Path
		result.Port = port
		result.Matched = urlString
	}
	return results, nil
}

// compileOfflineHTTPRequest iterates all requests if offline http mode is
// specified and collects all matchers for all the base request templates
// (those with URL {{BaseURL}} and it's slash variation.)
func compileOfflineHTTPRequest(template *templates.Template, options *protocols.ExecutorOptions) error {
	operatorsList := []*operators.Operators{}

	for _, req := range template.RequestsHTTP {
		operatorsList = append(operatorsList, &req.Operators)
	}
	if len(operatorsList) > 0 {
		options.Operators = operatorsList
		var err error

		request := &offlinehttp.Request{}
		_ = request.Compile(options)
		template.Executer, err = tmplexec.NewTemplateExecuter([]protocols.Request{request}, options)
		return err
	}
	return nil
}
