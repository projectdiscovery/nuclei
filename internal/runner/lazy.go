package runner

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type AuthLazyFetchOptions struct {
	TemplateStore *loader.Store
	ExecOpts      protocols.ExecutorOptions
	OnError       func(error)
}

// GetAuthTmplStore create new loader for loading auth templates
func GetAuthTmplStore(opts types.Options, catalog catalog.Catalog, execOpts protocols.ExecutorOptions) (*loader.Store, error) {
	tmpls := []string{}
	for _, file := range opts.SecretsFile {
		data, err := authx.GetTemplatePathsFromSecretFile(file)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("failed to get template paths from secrets file")
		}
		tmpls = append(tmpls, data...)
	}
	opts.Templates = tmpls
	opts.Workflows = nil
	opts.RemoteTemplateDomainList = nil
	opts.TemplateURLs = nil
	opts.WorkflowURLs = nil
	opts.ExcludedTemplates = nil
	opts.Tags = nil
	opts.ExcludeTags = nil
	opts.IncludeTemplates = nil
	opts.Authors = nil
	opts.Severities = nil
	opts.ExcludeSeverities = nil
	opts.IncludeTags = nil
	opts.IncludeIds = nil
	opts.ExcludeIds = nil
	opts.Protocols = nil
	opts.ExcludeProtocols = nil
	opts.IncludeConditions = nil
	cfg := loader.NewConfig(&opts, catalog, execOpts)
	cfg.StoreId = loader.AuthStoreId
	store, err := loader.New(cfg)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to initialize dynamic auth templates store")
	}
	return store, nil
}

// GetLazyAuthFetchCallback returns a lazy fetch callback for auth secrets
func GetLazyAuthFetchCallback(opts *AuthLazyFetchOptions) authx.LazyFetchSecret {
	return func(d *authx.Dynamic) error {
		tmpls := opts.TemplateStore.LoadTemplates([]string{d.TemplatePath})
		if len(tmpls) == 0 {
			return fmt.Errorf("no templates found for path: %s", d.TemplatePath)
		}
		if len(tmpls) > 1 {
			return fmt.Errorf("multiple templates found for path: %s", d.TemplatePath)
		}
		data := map[string]interface{}{}
		tmpl := tmpls[0]
		// add args to tmpl here
		vars := map[string]interface{}{}
		mainCtx := context.Background()
		ctx := scan.NewScanContext(mainCtx, contextargs.NewWithInput(mainCtx, d.Input))

		cliVars := map[string]interface{}{}
		if opts.ExecOpts.Options != nil {
			// gets variables passed from cli -v and -env-vars
			cliVars = generators.BuildPayloadFromOptions(opts.ExecOpts.Options)
		}

		for _, v := range d.Variables {
			//  Check if the template has any env variables and expand them
			if strings.HasPrefix(v.Value, "$") {
				env.ExpandWithEnv(&v.Value)
			}
			if strings.Contains(v.Value, "{{") {
				// if variables had value like {{username}}, then replace it with the value from cliVars
				// variables:
				//     - key: username
				//       value: {{username}}
				v.Value = replacer.Replace(v.Value, cliVars)
			}
			vars[v.Key] = v.Value
			ctx.Input.Add(v.Key, v.Value)
		}

		var finalErr error
		ctx.OnResult = func(e *output.InternalWrappedEvent) {
			if e == nil {
				finalErr = fmt.Errorf("no result found for template: %s", d.TemplatePath)
				return
			}
			if !e.HasOperatorResult() {
				finalErr = fmt.Errorf("no result found for template: %s", d.TemplatePath)
				return
			}
			// dynamic values
			for k, v := range e.OperatorsResult.DynamicValues {
				// Iterate through all the values and choose the
				// largest value as the extracted value
				for _, value := range v {
					oldVal, ok := data[k]
					if !ok || len(value) > len(oldVal.(string)) {
						data[k] = value
					}
				}
			}
			// named extractors
			for k, v := range e.OperatorsResult.Extracts {
				if len(v) > 0 {
					data[k] = v[0]
				}
			}
			if len(data) == 0 {
				if e.OperatorsResult.Matched {
					finalErr = fmt.Errorf("match found but no (dynamic/extracted) values found for template: %s", d.TemplatePath)
				} else {
					finalErr = fmt.Errorf("no match or (dynamic/extracted) values found for template: %s", d.TemplatePath)
				}
			}
			// log result of template in result file/screen
			_ = writer.WriteResult(e, opts.ExecOpts.Output, opts.ExecOpts.Progress, opts.ExecOpts.IssuesClient)
		}
		_, err := tmpl.Executer.ExecuteWithResults(ctx)
		if err != nil {
			finalErr = err
		}
		// store extracted result in auth context
		d.Extracted = data
		if finalErr != nil && opts.OnError != nil {
			opts.OnError(finalErr)
		}
		return finalErr
	}
}
