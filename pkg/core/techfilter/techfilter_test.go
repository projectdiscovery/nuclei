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
