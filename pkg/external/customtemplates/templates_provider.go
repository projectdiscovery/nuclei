package customtemplates

import (
	"context"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
)

type Provider interface {
	Download(ctx context.Context)
	Update(ctx context.Context)
}

// CustomTemplatesManager is a manager for custom templates
type CustomTemplatesManager struct {
	providers []Provider
}

// Download downloads the custom templates
func (c *CustomTemplatesManager) Download(ctx context.Context) {
	for _, provider := range c.providers {
		provider.Download(ctx)
	}
}

// Update updates the custom templates
func (c *CustomTemplatesManager) Update(ctx context.Context) {
	for _, provider := range c.providers {
		provider.Update(ctx)
	}
}

// NewCustomTemplatesManager returns a new instance of a custom templates manager
func NewCustomTemplatesManager(options *types.Options) (*CustomTemplatesManager, error) {
	ctm := &CustomTemplatesManager{providers: []Provider{}}

	// Add GitHub providers
	githubProviders, err := NewGitHubProviders(options)
	if err != nil {
		errx := errkit.FromError(err)
		errx.Msgf("could not create github providers for custom templates")
		return nil, errx
	}
	for _, v := range githubProviders {
		ctm.providers = append(ctm.providers, v)
	}

	// Add AWS S3 providers
	s3Providers, err := NewS3Providers(options)
	if err != nil {
		errx := errkit.FromError(err)
		errx.Msgf("could not create s3 providers for custom templates")
		return nil, errx
	}
	for _, v := range s3Providers {
		ctm.providers = append(ctm.providers, v)
	}

	// Add Azure providers
	azureProviders, err := NewAzureProviders(options)
	if err != nil {
		errx := errkit.FromError(err)
		errx.Msgf("could not create azure providers for custom templates")
		return nil, errx
	}
	for _, v := range azureProviders {
		ctm.providers = append(ctm.providers, v)
	}

	// Add GitLab providers
	gitlabProviders, err := NewGitLabProviders(options)
	if err != nil {
		errx := errkit.FromError(err)
		errx.Msgf("could not create gitlab providers for custom templates")
		return nil, errx
	}
	for _, v := range gitlabProviders {
		ctm.providers = append(ctm.providers, v)
	}

	return ctm, nil
}
