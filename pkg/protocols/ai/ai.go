// Package ai implements the ai protocol: a prompt based authoring layer that
// expands into concrete nuclei requests when a template is loaded.
//
// Prompts are never evaluated during a scan. Each prompt is resolved once into
// a template fragment, pinned by digest and cached on disk, then executed as
// ordinary nuclei requests. Scan behaviour therefore stays deterministic, and
// the materialised fragment can be reviewed and committed like any other
// template.
package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/utils/errkit"
)

// fragmentSchemaVersion is mixed into the prompt digest so that a change to the
// capability surface we hand the resolver invalidates previously pinned
// expansions instead of silently reusing a fragment built against old rules.
const fragmentSchemaVersion = "1"

// Request is a prompt backed request definition. It carries no execution
// behaviour of its own: Expand turns it into the protocol requests that
// actually run.
type Request struct {
	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID is the optional ID of the Request"`
	// description: |
	//   Prompt describes, in natural language, what the template should do.
	//   It is mapped onto nuclei protocol primitives when the template loads.
	// examples:
	//   - value: "\"GET /admin and flag responses that are a working admin login form\""
	Prompt string `yaml:"prompt" json:"prompt" jsonschema:"title=prompt describing the check,description=Natural language description of the check to perform"`
	// description: |
	//   Model optionally pins the resolver model used to expand the prompt.
	Model string `yaml:"model,omitempty" json:"model,omitempty" jsonschema:"title=resolver model,description=Model used to expand the prompt into protocol requests"`
	// description: |
	//   Expansion pins the digest of the fragment this prompt resolved to.
	//   Nuclei writes it on first expansion and refuses to run if a later
	//   expansion disagrees, so a template cannot silently change meaning.
	Expansion string `yaml:"expansion,omitempty" json:"expansion,omitempty" jsonschema:"title=pinned expansion digest,description=Digest of the protocol fragment this prompt resolved to"`
}

// Fragment is the set of protocol requests a prompt expands into.
//
// Only http is supported today. The field is deliberately shaped like the
// template request blocks so a fragment can be read, diffed and committed as
// ordinary template YAML.
type Fragment struct {
	HTTP []*http.Request `yaml:"http,omitempty" json:"http,omitempty"`
}

// IsEmpty returns true when a fragment carries no requests.
func (fragment *Fragment) IsEmpty() bool {
	return fragment == nil || len(fragment.HTTP) == 0
}

// EffectiveModel returns the model that will expand this prompt: the one the
// template pins, falling back to the resolver default.
func (request *Request) EffectiveModel(fallback string) string {
	if request.Model != "" {
		return request.Model
	}

	return fallback
}

// CacheKey returns the cache key for the request. It covers everything that can
// change the resolved fragment, the model included, so switching models
// re-resolves instead of silently reusing another model's expansion.
func (request *Request) CacheKey(model string) string {
	hasher := sha256.New()
	for _, part := range []string{fragmentSchemaVersion, model, strings.TrimSpace(request.Prompt)} {
		_, _ = hasher.Write([]byte(part))
		// separator prevents distinct field splits hashing to the same value
		_, _ = hasher.Write([]byte{0})
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// FragmentDigest returns the digest of a resolved fragment.
//
// The pin is over the fragment rather than over the prompt so that a template
// shared with a pin still loads under any model that produces the same
// requests, and still objects the moment the requests differ.
func FragmentDigest(fragment []byte) string {
	sum := sha256.Sum256(fragment)

	return hex.EncodeToString(sum[:])
}

// ExpandOptions carries the collaborators Expand needs.
type ExpandOptions struct {
	// Resolver is built only on a cache miss, so a scan whose prompts are
	// already cached runs with no provider configured and no network access.
	Resolver func() (Resolver, error)
	// Store caches resolved fragments across runs.
	Store *Store
	// Model is the resolver default, used when a request pins no model itself.
	Model string
}

// Expand resolves the prompt into protocol requests.
//
// The cache is authoritative: a prompt that has been resolved before never
// reaches the resolver again, which is what keeps repeat scans identical and
// keeps cost proportional to the number of templates rather than targets.
func (request *Request) Expand(ctx context.Context, options ExpandOptions) (*Fragment, error) {
	if strings.TrimSpace(request.Prompt) == "" {
		return nil, errkit.New("ai request has no prompt")
	}

	model := request.EffectiveModel(options.Model)
	key := request.CacheKey(model)

	raw, err := options.Store.Get(key)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		if options.Resolver == nil {
			return nil, errkit.Newf("no ai resolver configured and prompt %s is not cached", key)
		}

		resolver, resolverErr := options.Resolver()
		if resolverErr != nil {
			return nil, resolverErr
		}

		if raw, err = resolver.Resolve(ctx, request.Prompt, model); err != nil {
			return nil, errkit.Wrap(err, "could not resolve prompt")
		}

		if err = options.Store.Put(key, raw); err != nil {
			return nil, err
		}
	}

	// validated on every load, not just on resolution, so a hand edited or
	// tampered cache entry cannot introduce a template that matches everything
	if err = validateFragment(raw); err != nil {
		return nil, errkit.Wrapf(err, "invalid expansion for prompt %s", key)
	}

	digest := FragmentDigest(raw)
	if request.Expansion != "" && request.Expansion != digest {
		return nil, errkit.Newf("pinned expansion %s does not match the resolved requests (%s), review the expansion and regenerate the template", request.Expansion, digest)
	}

	fragment := &Fragment{}
	if err = yaml.Unmarshal(raw, fragment); err != nil {
		return nil, errkit.Wrap(err, "could not parse resolved fragment")
	}

	request.Expansion = digest

	return fragment, nil
}
