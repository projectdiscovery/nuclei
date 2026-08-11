// Package techfilter maps Wappalyzer products/categories to template tags and
// decides whether a template can produce a finding on a fingerprinted host.
//
// Fail-open rules (coverage over aggressiveness):
//   - templates with no product/macro tags always run
//   - hosts with no fingerprints always allow every template
//   - non-HTTP templates are not filtered here (reachability owns that)
package techfilter

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// genericTags are common nuclei tags that do not bind a template to a product.
var genericTags = map[string]struct{}{
	"cve": {}, "cnvd": {}, "edb": {}, "kev": {}, "vkev": {},
	"misconfig": {}, "exposure": {}, "config": {}, "disclosure": {},
	"tech": {}, "detect": {}, "fingerprint": {}, "favicon": {}, "waf": {},
	"http": {}, "network": {}, "dns": {}, "ssl": {}, "tls": {},
	"websocket": {}, "headless": {}, "file": {}, "code": {}, "javascript": {},
	"workflow": {}, "intrusive": {}, "dos": {}, "fuzz": {}, "token-spray": {},
	"osint": {}, "panel": {}, "login": {}, "auth": {}, "unauth": {},
	"default-login": {}, "vuln": {}, "rce": {}, "lfi": {}, "sqli": {},
	"xss": {}, "ssrf": {}, "xxe": {}, "ssti": {}, "idor": {},
	"critical": {}, "high": {}, "medium": {}, "low": {}, "info": {},
	"unknown": {}, "generic": {}, "misc": {}, "bench": {},
}

// productAliases normalize common nuclei / wappalyzer spellings to one token.
var productAliases = map[string]string{
	"wp":                 "wordpress",
	"httpd":              "apache",
	"apache-http-server": "apache",
}

// categoryMacros maps Wappalyzer category names to short macro tags.
var categoryMacros = map[string]string{
	"cms":                   "cms",
	"ecommerce":             "ecommerce",
	"web servers":           "webserver",
	"web-servers":           "webserver",
	"web frameworks":        "web-framework",
	"web-frameworks":        "web-framework",
	"javascript frameworks": "js-framework",
	"javascript-frameworks": "js-framework",
	"javascript libraries":  "js-library",
	"javascript-libraries":  "js-library",
	"cdn":                   "cdn",
	"databases":             "database",
	"programming languages": "language",
	"programming-languages": "language",
	"paas":                  "paas",
	"saas":                  "saas",
	"security":              "security",
	"caching":               "caching",
	"miscellaneous":         "misc",
}

// HostProfile is the set of product + macro tags inferred for one target.
type HostProfile struct {
	Tags map[string]struct{} // empty / nil => unknown => fail-open
}

// HasTags reports whether fingerprinting produced at least one tag.
func (h HostProfile) HasTags() bool {
	return len(h.Tags) > 0
}

// NormalizeProduct turns a Wappalyzer / nuclei product name into a tag token.
func NormalizeProduct(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return ""
	}
	if i := strings.IndexByte(name, ':'); i > 0 {
		name = name[:i]
	}
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.Join(strings.Fields(name), "-")
	if alias, ok := productAliases[name]; ok {
		return alias
	}
	return name
}

// NormalizeCategory turns a Wappalyzer category into a macro tag.
func NormalizeCategory(cat string) string {
	key := strings.ToLower(strings.TrimSpace(cat))
	if key == "" {
		return ""
	}
	if m, ok := categoryMacros[key]; ok {
		return m
	}
	return strings.ReplaceAll(key, " ", "-")
}

// IsGenericTag reports whether tag is not product/macro binding.
func IsGenericTag(tag string) bool {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return true
	}
	_, ok := genericTags[tag]
	return ok
}

// ProfileFromFingerprint builds a host profile from products and their categories.
// products maps product name -> category names from Wappalyzer.
func ProfileFromFingerprint(products map[string][]string) HostProfile {
	tags := make(map[string]struct{})
	for product, cats := range products {
		if p := NormalizeProduct(product); p != "" {
			tags[p] = struct{}{}
		}
		for _, c := range cats {
			if m := NormalizeCategory(c); m != "" {
				tags[m] = struct{}{}
			}
		}
	}
	return HostProfile{Tags: tags}
}

// TemplateProductTags returns product/macro tags that bind a template to a stack.
// Empty means the template is generic and must always be allowed.
func TemplateProductTags(t *templates.Template) []string {
	if t == nil {
		return nil
	}
	raw := t.Info.Tags.ToSlice()
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, tag := range raw {
		tag = NormalizeProduct(tag)
		if tag == "" || IsGenericTag(tag) {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

// IsTechBound reports whether the template is constrained to a product/macro.
func IsTechBound(t *templates.Template) bool {
	return len(TemplateProductTags(t)) > 0
}

// Allow reports whether template may run on a host with the given profile.
// Fail-open when the host was not fingerprinted or the template is unbound.
func Allow(profile HostProfile, t *templates.Template) bool {
	if t == nil {
		return true
	}
	bound := TemplateProductTags(t)
	if len(bound) == 0 {
		return true
	}
	if !profile.HasTags() {
		return true
	}
	for _, tag := range bound {
		if _, ok := profile.Tags[tag]; ok {
			return true
		}
	}
	return false
}

// CountTechBound returns how many templates carry product/macro tags.
func CountTechBound(tpls []*templates.Template) int {
	n := 0
	for _, t := range tpls {
		if IsTechBound(t) {
			n++
		}
	}
	return n
}
