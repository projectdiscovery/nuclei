package runner

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/autologin"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
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
	"github.com/projectdiscovery/utils/errkit"
)

type AuthLazyFetchOptions struct {
	TemplateStore *loader.Store
	ExecOpts      *protocols.ExecutorOptions
	OnError       func(error)
}

// GetAuthTmplStore create new loader for loading auth templates
func GetAuthTmplStore(opts *types.Options, catalog catalog.Catalog, execOpts *protocols.ExecutorOptions) (*loader.Store, error) {
	tmpls := []string{}
	for _, file := range opts.SecretsFile {
		data, err := authx.GetTemplatePathsFromSecretFile(file)
		if err != nil {
			return nil, errkit.Wrap(err, "failed to get template paths from secrets file")
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
	cfg := loader.NewConfig(opts, catalog, execOpts)
	cfg.StoreId = loader.AuthStoreId
	store, err := loader.New(cfg)
	if err != nil {
		return nil, errkit.Wrap(err, "failed to initialize dynamic auth templates store")
	}
	return store, nil
}

// buildAutoLoginRuntimeOptions maps scan-level options into the auto-login
// runtime options so a (headless) auto-login uses the same identity and network
// path as the scan: user-agent and custom headers (-H), proxy, CDP endpoint and
// Chrome settings.
func buildAutoLoginRuntimeOptions(opts *types.Options) *authx.AutoLoginRuntimeOptions {
	// Mirror the proxy precedence used everywhere else in the codebase (HTTP
	// proxy first, SOCKS as fallback) so a SOCKS-proxied scan does not silently
	// bypass the proxy during auto-login.
	proxy := opts.AliveHttpProxy
	if proxy == "" {
		proxy = opts.AliveSocksProxy
	}
	rt := &authx.AutoLoginRuntimeOptions{
		Proxy:              proxy,
		CDPEndpoint:        opts.CDPEndpoint,
		UseInstalledChrome: opts.UseInstalledChrome,
		ShowBrowser:        opts.ShowBrowser,
	}
	for _, header := range opts.CustomHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		if strings.EqualFold(key, "User-Agent") {
			rt.UserAgent = value
			continue
		}
		if rt.CustomHeaders == nil {
			rt.CustomHeaders = map[string]string{}
		}
		rt.CustomHeaders[key] = value
	}
	return rt
}

// autoLoginStoreFromOptions assembles an in-memory Authx store containing a
// single auto-login dynamic secret built from the -auth-login-url flag set. The
// captured session is scoped to the login URL's host.
func autoLoginStoreFromOptions(opts *types.Options) (*authx.Authx, error) {
	// The login URL may be supplied directly (-auth-login-url) or derived from a
	// recording's first navigate step; resolve the host scope from whichever is
	// available.
	loginURL := opts.AuthLoginURL
	if loginURL == "" && opts.AuthRecording != "" {
		steps, err := autologin.StepsFromRecordingFile(opts.AuthRecording, opts.AuthUsername, opts.AuthPassword)
		if err != nil {
			return nil, err
		}
		loginURL = autologin.FirstNavigateURL(steps)
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		return nil, errkit.Wrap(err, "invalid auto-login url")
	}
	if u.Host == "" {
		return nil, errkit.New("auto-login: could not determine host (set -auth-login-url or provide a recording with a navigate step)")
	}
	return &authx.Authx{
		ID: "cli-auto-login",
		Dynamic: []authx.Dynamic{
			{
				Secret: &authx.Secret{Domains: []string{u.Host}},
				AutoLogin: &authx.AutoLoginConfig{
					LoginURL:      loginURL,
					Username:      opts.AuthUsername,
					Password:      opts.AuthPassword,
					UsernameField: opts.AuthUsernameField,
					PasswordField: opts.AuthPasswordField,
					Headless:      opts.AuthHeadless,
					Recording:     opts.AuthRecording,
				},
			},
		},
	}, nil
}

// GetLazyAuthFetchCallback returns a lazy fetch callback for auth secrets
func GetLazyAuthFetchCallback(opts *AuthLazyFetchOptions) authx.LazyFetchSecret {
	return func(d *authx.Dynamic) error {
		tmpls, err := opts.TemplateStore.LoadTemplates([]string{d.TemplatePath})
		if err != nil {
			return fmt.Errorf("failed to load templates: %w", err)
		}
		if len(tmpls) == 0 {
			return fmt.Errorf("%w for path: %s", disk.ErrNoTemplatesFound, d.TemplatePath)
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
				return
			}
			if !e.HasOperatorResult() {
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
			// log result of template in result file/screen
			_ = writer.WriteResult(e, opts.ExecOpts.Output, opts.ExecOpts.Progress, opts.ExecOpts.IssuesClient)
		}
		_, execErr := tmpl.Executer.ExecuteWithResults(ctx)
		if execErr != nil {
			finalErr = execErr
		}
		if finalErr == nil && len(data) == 0 {
			finalErr = fmt.Errorf("no extracted values found for template: %s", d.TemplatePath)
		}
		// store extracted result in auth context
		d.Extracted = data
		if finalErr != nil && opts.OnError != nil {
			opts.OnError(finalErr)
		}
		return finalErr
	}
}
