package templates

import (
	"context"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/ai"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/utils/errkit"
)

// expandAIRequests maps every ai prompt in the template onto the protocol
// requests it describes.
//
// This runs once per template load rather than per target, which is what keeps
// prompts out of the scan path entirely: by the time the executer is built the
// template is indistinguishable from a hand written one.
//
// Expansion is skipped when -ai is not set so that a prompt is never sent
// anywhere for a template the user has not opted into running. Such templates
// keep their unexpanded ai requests and are excluded by the capability check at
// load time with the usual missing flag message.
func (template *Template) expandAIRequests(options *protocols.ExecutorOptions) error {
	if template.aiExpanded || !template.HasAIRequest() {
		return nil
	}

	if options.Options == nil || !options.Options.EnableAITemplates {
		return nil
	}

	expandOptions := ai.ExpandOptions{
		Resolver: func() (ai.Resolver, error) {
			if registered := ai.RegisteredResolver(); registered != nil {
				return registered, nil
			}

			return ai.NewResolver(ai.ProviderConfig{
				Provider: options.Options.AIProvider,
				BaseURL:  options.Options.AIBaseURL,
				Model:    options.Options.AIModel,
				Timeout:  options.Options.AITimeout,
			})
		},
		Store: ai.NewStore(options.Options.AICacheDirectory),
		Model: options.Options.AIModel,
	}

	for _, request := range template.RequestsAI {
		if request == nil {
			continue
		}

		fragment, err := request.Expand(context.Background(), expandOptions)
		if err != nil {
			return errkit.Wrapf(err, "could not expand ai request for %s", template.ID)
		}

		// RequestsHTTP is the canonical field: UnmarshalYAML has already folded
		// the http key into it by the time expansion runs
		template.RequestsHTTP = append(template.RequestsHTTP, fragment.HTTP...)

		logExpandedFragment(template, request, fragment)
	}

	template.aiExpanded = true

	return nil
}

// logExpandedFragment surfaces what a prompt actually resolved to. The prompt is
// the whole template here, so an author who never sees the materialised
// requests has no way to tell a correct expansion from a plausible wrong one.
func logExpandedFragment(template *Template, request *ai.Request, fragment *ai.Fragment) {
	materialised, err := yaml.Marshal(fragment)
	if err != nil {
		return
	}

	gologger.Verbose().Msgf("[%s] ai prompt expanded to %s\n%s", template.ID, request.Expansion, string(materialised))
}
