package targetprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/require"
)

const templatesDir = "/templates"

func newTemplate(path, id string, sev severity.Severity, product string, tags ...string) *templates.Template {
	info := model.Info{
		Tags:           stringslice.StringSlice{Value: tags},
		SeverityHolder: severity.Holder{Severity: sev},
	}
	if product != "" {
		info.Metadata = map[string]any{"product": product}
	}
	return &templates.Template{ID: id, Path: filepath.Join(templatesDir, path), Info: info}
}

var (
	thinkphpRCE  = newTemplate("http/cves/thinkphp-rce.yaml", "thinkphp-rce", severity.Critical, "thinkphp", "cve", "thinkphp", "rce")
	tomcatPanel  = newTemplate("http/exposed-panels/tomcat-panel.yaml", "tomcat-panel", severity.Info, "tomcat", "panel", "tomcat")
	ghostcat     = newTemplate("network/cves/CVE-2020-1938.yaml", "CVE-2020-1938", severity.Critical, "geode", "cve", "apache", "tomcat")
	gitConfig    = newTemplate("http/exposures/git-config.yaml", "git-config", severity.Medium, "", "exposure", "git")
	allTemplates = []*templates.Template{thinkphpRCE, tomcatPanel, ghostcat, gitConfig}
)

func selected(t *testing.T, r *Registry, input string) []string {
	t.Helper()
	selection := r.For(&contextargs.MetaInput{Input: input})
	var ids []string
	for _, tpl := range allTemplates {
		if selection == nil || selection.Allows(tpl.Path) {
			ids = append(ids, tpl.ID)
		}
	}
	return ids
}

func bindLine(t *testing.T, r *Registry, line string) string {
	t.Helper()
	parsed, err := r.ParseLine(line)
	require.NoError(t, err)
	r.Bind(&contextargs.MetaInput{Input: parsed.Target, CustomIP: parsed.IP}, parsed.Selection)
	return parsed.Target
}

func input(target string) *contextargs.MetaInput {
	return &contextargs.MetaInput{Input: target}
}

func TestParseLineRejectsInvalidLines(t *testing.T) {
	r := NewRegistry(templatesDir)
	for name, line := range map[string]string{
		"malformed json":   `{"target": "a.com"`,
		"missing target":   `{"tags": ["cve"]}`,
		"unknown key":      `{"target": "a.com", "tag": ["cve"]}`,
		"invalid severity": `{"target": "a.com", "severity": ["urgent"]}`,
		"invalid type":     `{"target": "a.com", "type": ["smtp"]}`,
		"non string value": `{"target": "a.com", "tags": [1]}`,
		"missing profile":  `{"target": "a.com", "profile": "does-not-exist"}`,
		"non string ip":    `{"target": "a.com", "ip": 10}`,
		"invalid ip":       `{"target": "a.com", "ip": "10.0.0"}`,
		"ip with zone":     `{"target": "a.com", "ip": "fe80::1%eth0"}`,
		"unspecified ip":   `{"target": "a.com", "ip": "0.0.0.0"}`,
		"ip target":        `{"target": "https://192.0.2.1", "ip": "192.0.2.10"}`,
		"cidr target":      `{"target": "192.0.2.0/24", "ip": "192.0.2.10"}`,
		"asn target":       `{"target": "AS13335", "ip": "192.0.2.10"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r.ParseLine(line)
			require.Error(t, err)
		})
	}
}

func TestParseLineIP(t *testing.T) {
	r := NewRegistry(templatesDir)
	for line, want := range map[string]Line{
		`{"target": "https://a.com", "ip": "192.0.2.10"}`:             {Target: "https://a.com", IP: "192.0.2.10"},
		`{"target": "a.com:8443", "ip": " 2001:DB8::1 "}`:             {Target: "a.com:8443", IP: "2001:db8::1"},
		`{"target": "a.com", "ip": "::ffff:192.0.2.10"}`:              {Target: "a.com", IP: "192.0.2.10"},
		`{"target": "a.com"}`:                                         {Target: "a.com"},
		`{"target": "https://a.com", "ip": "192.0.2.10", "tags": []}`: {Target: "https://a.com", IP: "192.0.2.10"},
	} {
		t.Run(line, func(t *testing.T) {
			parsed, err := r.ParseLine(line)
			require.NoError(t, err)
			require.Equal(t, want, parsed)
		})
	}
	require.False(t, r.Scoped(), "lines that only set an ip do not scope the scan")
	require.Nil(t, r.LoadFilter())
}

func TestPinnedTargetsKeepTheirSelection(t *testing.T) {
	r := NewRegistry(templatesDir)
	bindLine(t, r, `{"target": "https://a.com", "ip": "192.0.2.10", "tags": ["thinkphp"]}`)
	bindLine(t, r, `{"target": "https://a.com", "ip": "192.0.2.11", "tags": ["tomcat"]}`)
	bindLine(t, r, `{"target": "https://a.com", "ip": "192.0.2.12"}`)
	r.Prepare(allTemplates)

	selectedFor := func(ip string) []string {
		selection := r.For(&contextargs.MetaInput{Input: "https://a.com", CustomIP: ip})
		var ids []string
		for _, tpl := range allTemplates {
			if selection == nil || selection.Allows(tpl.Path) {
				ids = append(ids, tpl.ID)
			}
		}
		return ids
	}
	require.Equal(t, []string{"thinkphp-rce"}, selectedFor("192.0.2.10"))
	require.Equal(t, []string{"tomcat-panel", "CVE-2020-1938"}, selectedFor("192.0.2.11"))
	require.Equal(t, []string{"thinkphp-rce", "tomcat-panel", "CVE-2020-1938", "git-config"}, selectedFor("192.0.2.12"))
}

func TestProfileMustBeAnID(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "profiles"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "profiles", "php.yml"), []byte("tags: [thinkphp]\n"), 0o600))
	outside := filepath.Join(dir, "outside.yml")
	require.NoError(t, os.WriteFile(outside, []byte("tags: [tomcat]\n"), 0o600))

	r := NewRegistry(dir)
	for _, profile := range []string{outside, "../outside.yml", "../outside", "profiles/php.yml", "php.yml", `profiles\php`, ".."} {
		t.Run(profile, func(t *testing.T) {
			line, err := json.Marshal(map[string]string{"target": "a.com", "profile": profile})
			require.NoError(t, err)
			_, err = r.ParseLine(string(line))
			require.ErrorContains(t, err, "profile ID")
		})
	}

	parsed, err := r.ParseLine(`{"target": "a.com", "profile": "php"}`)
	require.NoError(t, err)
	require.Equal(t, []string{"thinkphp"}, parsed.Selection.rules[0].filter.Tags)
}

func TestSelectionFilters(t *testing.T) {
	r := NewRegistry(templatesDir)
	tags := bindLine(t, r, `{"target": "https://a.com", "tags": ["thinkphp"]}`)
	commaTags := bindLine(t, r, `{"target": "https://b.com", "tags": "tomcat, exposure"}`)
	sev := bindLine(t, r, `{"target": "https://c.com", "severity": ["critical"], "exclude-id": ["CVE-2020-1938"]}`)
	paths := bindLine(t, r, `{"target": "https://d.com", "templates": ["http/"]}`)
	r.Prepare(allTemplates)

	require.Equal(t, []string{"thinkphp-rce"}, selected(t, r, tags))
	require.Equal(t, []string{"tomcat-panel", "CVE-2020-1938", "git-config"}, selected(t, r, commaTags))
	require.Equal(t, []string{"thinkphp-rce"}, selected(t, r, sev))
	require.Equal(t, []string{"thinkphp-rce", "tomcat-panel", "git-config"}, selected(t, r, paths))
	require.Equal(t, []string{"thinkphp-rce", "tomcat-panel", "CVE-2020-1938", "git-config"}, selected(t, r, "https://unlisted.com"))
}

func TestSelectionTech(t *testing.T) {
	r := NewRegistry(templatesDir)
	tomcat := bindLine(t, r, `{"target": "https://a.com", "tech": ["Apache Tomcat"]}`)
	php := bindLine(t, r, `{"target": "https://b.com", "tech": ["ThinkPHP"], "severity": ["critical", "medium"]}`)
	r.Prepare(allTemplates)

	// product-bound templates follow the tech list, generic ones always run;
	// Ghostcat declares product "geode" but is kept by its tomcat tag
	require.Equal(t, []string{"tomcat-panel", "CVE-2020-1938", "git-config"}, selected(t, r, tomcat))
	require.Equal(t, []string{"thinkphp-rce", "git-config"}, selected(t, r, php))
}

func TestProfileWithInlineOverride(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "profiles"), 0o755))
	profile := "code: true\ntags:\n  - thinkphp\nseverity:\n  - info\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "profiles", "php.yml"), []byte(profile), 0o600))

	r := NewRegistry(dir)
	parsed, err := r.ParseLine(`{"target": "https://a.com", "profile": "php", "severity": "critical"}`)
	require.NoError(t, err)
	require.Len(t, parsed.Selection.rules, 1)
	require.Equal(t, []string{"thinkphp"}, parsed.Selection.rules[0].filter.Tags)
	require.Equal(t, []severity.Severity{severity.Critical}, parsed.Selection.rules[0].filter.Severities)
	require.Equal(t, "https://a.com", parsed.Target)
}

func TestDuplicateTargetsMerge(t *testing.T) {
	r := NewRegistry(templatesDir)
	phpLine, err := r.ParseLine(`{"target": "https://a.com", "tags": ["thinkphp"]}`)
	require.NoError(t, err)
	tomcatLine, err := r.ParseLine(`{"target": "https://a.com", "tags": ["tomcat"]}`)
	require.NoError(t, err)
	php, tomcat := phpLine.Selection, tomcatLine.Selection

	r.Bind(input("https://a.com"), php)
	r.Merge(input("https://a.com"), tomcat)
	r.Merge(input("https://a.com"), php)
	r.Bind(input("https://b.com"), php)
	r.Merge(input("https://b.com"), nil)
	r.Bind(input("https://c.com"), nil)
	r.Merge(input("https://c.com"), php)
	r.Prepare(allTemplates)

	require.Equal(t, []string{"thinkphp-rce", "tomcat-panel", "CVE-2020-1938"}, selected(t, r, "https://a.com"))
	require.Nil(t, r.For(&contextargs.MetaInput{Input: "https://b.com"}), "a plain duplicate lifts the restriction")
	require.Nil(t, r.For(&contextargs.MetaInput{Input: "https://c.com"}), "a plain target stays unrestricted")

	again, err := r.ParseLine(`{"target": "https://z.com", "tags": ["thinkphp"]}`)
	require.NoError(t, err)
	require.Same(t, php, again.Selection, "identical selectors are interned")
}

func TestLoadFilter(t *testing.T) {
	t.Run("union of selections", func(t *testing.T) {
		r := NewRegistry(templatesDir)
		bindLine(t, r, `{"target": "https://a.com", "tags": ["thinkphp"]}`)
		bindLine(t, r, `{"target": "https://b.com", "tech": ["tomcat"], "severity": ["info"]}`)
		filter := r.LoadFilter()
		require.NotNil(t, filter)

		r.Prepare(allTemplates)
		var loaded []string
		for _, tpl := range allTemplates {
			if filter(r.metadata[tpl.Path]) {
				loaded = append(loaded, tpl.ID)
			}
		}
		require.Equal(t, []string{"thinkphp-rce", "tomcat-panel"}, loaded)
	})

	t.Run("unrestricted target loads everything", func(t *testing.T) {
		r := NewRegistry(templatesDir)
		bindLine(t, r, `{"target": "https://a.com", "tags": ["thinkphp"]}`)
		r.Bind(input("https://b.com"), nil)
		require.Nil(t, r.LoadFilter())
	})

	t.Run("plain duplicate of a target line loads everything", func(t *testing.T) {
		r := NewRegistry(templatesDir)
		target := bindLine(t, r, `{"target": "https://a.com", "tags": ["thinkphp"]}`)
		r.Merge(input(target), nil)
		require.Nil(t, r.LoadFilter())
	})
}

func TestTechTokens(t *testing.T) {
	for tech, want := range map[string][]string{
		"nginx":         {"nginx"},
		"ThinkPHP":      {"thinkphp"},
		"apache_tomcat": {"apache-tomcat"},
		"Apache Tomcat": {"apache-tomcat", "apache", "tomcat"},
		"apache:tomcat": {"apache-tomcat", "apache", "tomcat"},
		"Microsoft IIS": {"microsoft-iis", "microsoft", "iis"},
		"  ":            nil,
	} {
		require.Equal(t, want, techTokens(tech), tech)
	}
}
