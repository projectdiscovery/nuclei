package techfilter

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

func TestNormalizeProductAndCategory(t *testing.T) {
	if got := NormalizeProduct("Nginx:1.25"); got != "nginx" {
		t.Fatalf("NormalizeProduct = %q", got)
	}
	if got := NormalizeProduct("wp"); got != "wordpress" {
		t.Fatalf("alias = %q", got)
	}
	if got := NormalizeCategory("Web servers"); got != "webserver" {
		t.Fatalf("category = %q", got)
	}
}

func TestProfileFromFingerprint(t *testing.T) {
	p := ProfileFromFingerprint(map[string][]string{
		"Nginx":     {"Web servers"},
		"WordPress": {"CMS"},
	})
	for _, want := range []string{"nginx", "webserver", "wordpress", "cms"} {
		if _, ok := p.Tags[want]; !ok {
			t.Fatalf("missing tag %q in %#v", want, p.Tags)
		}
	}
}

func tagged(tags ...string) *templates.Template {
	return &templates.Template{
		Info: model.Info{Tags: stringslice.StringSlice{Value: tags}},
	}
}

func TestAllowFailOpenAndMatch(t *testing.T) {
	nginx := ProfileFromFingerprint(map[string][]string{"Nginx": {"Web servers"}})
	empty := HostProfile{}

	generic := tagged("misconfig", "http")
	wp := tagged("cve", "wordpress")
	ngx := tagged("nginx", "misconfig")
	cms := tagged("cms")

	if !Allow(nginx, generic) {
		t.Fatal("generic must always run")
	}
	if !Allow(empty, wp) {
		t.Fatal("unknown host must fail-open for bound templates")
	}
	if Allow(nginx, wp) {
		t.Fatal("wordpress template must not run on nginx-only host")
	}
	if !Allow(nginx, ngx) {
		t.Fatal("nginx template must run on nginx host")
	}
	if Allow(nginx, cms) {
		t.Fatal("cms-bound template must not run on nginx-only host")
	}
	wpHost := ProfileFromFingerprint(map[string][]string{"WordPress": {"CMS"}})
	if !Allow(wpHost, cms) {
		t.Fatal("cms macro must match wordpress host")
	}
	if !Allow(wpHost, wp) {
		t.Fatal("wordpress product must match")
	}
}

func TestMetaTagsAreNotTechBound(t *testing.T) {
	cases := [][]string{
		{"cve", "cve2021", "oast", "rce"},
		{"takeover", "dns"},
		{"hackerone", "packetstorm", "seclists"},
		{"wp-plugin", "wordpress-plugin"},
	}
	for _, tags := range cases {
		tpl := tagged(tags...)
		if IsTechBound(tpl) {
			t.Fatalf("tags %v must not be tech-bound, got %v", tags, TemplateProductTags(tpl))
		}
		cdnOnly := ProfileFromFingerprint(map[string][]string{"Cloudflare": {"CDN"}})
		if !Allow(cdnOnly, tpl) {
			t.Fatalf("unbound meta tags %v must run on any host", tags)
		}
	}
}

func TestCDNOnlyFingerprintFailOpen(t *testing.T) {
	cdnOnly := ProfileFromFingerprint(map[string][]string{"Cloudflare": {"CDN"}})
	if cdnOnly.HasSubstantiveTags() {
		t.Fatalf("cdn-only profile should not be substantive: %#v", cdnOnly.Tags)
	}
	wp := tagged("wordpress")
	if !Allow(cdnOnly, wp) {
		t.Fatal("CDN-only fingerprint must fail-open for product templates")
	}
}

func TestCountTechBound(t *testing.T) {
	n := CountTechBound([]*templates.Template{
		tagged("misconfig"),
		tagged("wordpress"),
		tagged("nginx", "http"),
		tagged("cve2023", "oast"),
	})
	if n != 2 {
		t.Fatalf("CountTechBound = %d", n)
	}
}

// A tag only binds when fingerprinting can emit it. nuclei-templates carries
// thousands of tags that name no product; binding to one of those prunes the
// template on every host, because no profile can ever contain it.
func TestOnlyKnownFingerprintTokensBind(t *testing.T) {
	nonProducts := [][]string{
		{"misconfig", "headers", "generic", "vuln"}, // http-missing-security-headers
		{"tech", "discovery"},                       // tech-detect
		{"waf", "tech", "misc", "discovery"},        // waf-detect
		{"wpscan"},
		{"top-100"}, {"top-200"},
		{"auth-bypass"}, {"time-based-sqli"},
		{"install"}, {"files"}, {"file-upload"},
		{"phishing"}, {"osint-social"},
		{"debug"}, {"devops"}, {"token"}, {"tokens"}, {"fpd"}, {"oss"},
	}
	nginx := ProfileFromFingerprint(map[string][]string{"Nginx": {"Web servers"}})
	for _, tags := range nonProducts {
		tpl := tagged(tags...)
		if got := TemplateProductTags(tpl); len(got) != 0 {
			t.Fatalf("tags %v must not bind, got %v", tags, got)
		}
		if !Allow(nginx, tpl) {
			t.Fatalf("unbound template %v must run on every host", tags)
		}
	}
}

// The inversion must not disable the filter: real products still bind, and a
// template for another stack is still pruned.
func TestKnownProductsStillBind(t *testing.T) {
	for _, tags := range [][]string{{"wordpress"}, {"apache"}, {"joomla"}, {"cms"}} {
		if got := TemplateProductTags(tagged(tags...)); len(got) == 0 {
			t.Fatalf("tags %v name a product and must bind", tags)
		}
	}

	nginx := ProfileFromFingerprint(map[string][]string{"Nginx": {"Web servers"}})
	if Allow(nginx, tagged("wordpress", "rce")) {
		t.Fatal("a wordpress template must not run on an nginx-only profile")
	}
	wp := ProfileFromFingerprint(map[string][]string{"WordPress": {"CMS"}})
	if !Allow(wp, tagged("wordpress", "rce")) {
		t.Fatal("a wordpress template must run on a wordpress profile")
	}
}

func TestKnownFingerprintTokensVocabulary(t *testing.T) {
	tokens := knownFingerprintTokens()
	if len(tokens) < 5000 {
		t.Fatalf("expected the wappalyzer vocabulary, got %d tokens", len(tokens))
	}
	for _, want := range []string{"wordpress", "nginx", "apache", "cms", "webserver"} {
		if _, ok := tokens[want]; !ok {
			t.Fatalf("token %q missing from the vocabulary", want)
		}
	}
	for _, bad := range []string{"discovery", "headers", "wpscan", "top-200"} {
		if _, ok := tokens[bad]; ok {
			t.Fatalf("token %q is not a product and must not be in the vocabulary", bad)
		}
	}
}
