package ai

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/utils/errkit"
)

// capabilityContract tells the resolver which nuclei primitives it may use.
//
// The prompt maps onto capabilities nuclei already has rather than onto free
// form behaviour, so the resolver can only ever produce something a template
// author could have written by hand.
const capabilityContract = `You translate a security check described in English into a nuclei template fragment.

Reply with YAML only. No prose, no markdown fences, no explanation.

The fragment must contain exactly one top-level key: http

Each http entry supports:
  method: GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS
  path: list of paths, using {{BaseURL}} or {{RootURL}} as the target prefix
  headers: map of request headers
  body: request body string
  redirects: bool, max-redirects: int
  matchers-condition: and | or
  matchers: list, each one of
    - type: status, with status: list of ints
    - type: word, with words: list of strings, part: body|header|all, condition: and|or, case-insensitive: bool
    - type: regex, with regex: list of RE2 patterns, part: body|header|all
    - type: size, with size: list of ints
    - type: dsl, with dsl: list of expressions over status_code, content_length, body, header, duration
    negative: true inverts a matcher
  extractors: list, each one of
    - type: regex, with regex: list of RE2 patterns and group: int
    - type: kval, with kval: list of header or cookie names
    - type: json, with json: list of jq style expressions
    - type: xpath, with xpath: list of expressions

Rules:
  Every http entry must define at least one matcher. A fragment without matchers
  reports every target as vulnerable and will be rejected.
  Prefer several narrow matchers combined with matchers-condition: and over one
  broad matcher, so the check does not fire on unrelated pages.
  Match on evidence specific to the issue, never on generic strings that appear
  on ordinary pages.
  Use only the keys listed above. Do not emit info, id, code, headless,
  javascript, network, ssl, proxy or interactsh keys.
  Send only requests the described check needs. Do not add extra probing.

Example reply:

http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Apache Server Status"
`

// allowedFragmentKeys are the top-level keys a resolved fragment may declare.
var allowedFragmentKeys = map[string]bool{"http": true}

// validateFragment rejects a resolved fragment before it can become a template.
//
// The resolver is untrusted input, so this checks shape rather than trusting
// the contract to have been followed. Unknown keys are an error rather than
// being ignored, otherwise a fragment declaring code or headless requests would
// silently parse as empty and hide what the model actually tried to do.
func validateFragment(raw []byte) error {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return errkit.New("fragment is empty")
	}

	keys := map[string]any{}
	if err := yaml.Unmarshal(raw, &keys); err != nil {
		return errkit.Wrap(err, "fragment is not valid yaml")
	}

	for key := range keys {
		if !allowedFragmentKeys[key] {
			return errkit.Newf("fragment declares unsupported key %q", key)
		}
	}

	fragment := &Fragment{}
	if err := yaml.Unmarshal(raw, fragment); err != nil {
		return errkit.Wrap(err, "fragment does not match the template schema")
	}

	if fragment.IsEmpty() {
		return errkit.New("fragment defines no http requests")
	}

	for index, request := range fragment.HTTP {
		if request == nil {
			return errkit.Newf("http request %d is empty", index)
		}

		// a request with no matchers reports every target as a finding, which is
		// the worst possible failure mode for a generated check
		if len(request.Matchers) == 0 {
			return errkit.Newf("http request %d defines no matchers", index)
		}
	}

	return nil
}
