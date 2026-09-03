package techgraph

import "strings"

// seedSynonyms maps common acronyms/aliases to a canonical tech id. This is the
// curated seed of the synonym table that the offline AI step later expands.
// Targets are validated against existing nodes at resolve time, so a stale entry
// simply has no effect.
var seedSynonyms = map[string]string{
	"aem":         "adobe:experience_manager",
	"coldfusion":  "adobe:coldfusion",
	"iis":         "microsoft:iis",
	"k8s":         "kubernetes:kubernetes",
	"springboot":  "vmware:spring_boot",
	"spring-boot": "vmware:spring_boot",
	"wls":         "oracle:weblogic_server",
	"weblogic":    "oracle:weblogic_server",
	"adfs":        "microsoft:active_directory_federation_services",
	// platform roots: ambiguous in the alias index (collide with sub-product
	// nodes like keydatas:wordpress) so pin them to the canonical platform node.
	"wordpress": "wordpress",
	"drupal":    "drupal",
	"joomla":    "joomla",
	"magento":   "magento",
}

// genericTokens are tags/aliases that are not products and must never be used as
// a tag/id/dir-reconciliation key (they would mis-attach templates to random
// techs). This list intentionally includes common English words that also happen
// to be CPE product names (dashboard, gateway, console, ...), platform/OS tokens
// (linux, windows, android, ...), and category labels (generic, audit, ...),
// since those were the dominant source of false attachments.
var genericTokens = map[string]bool{
	// vuln classes / scan vocabulary
	"cve": true, "cves": true, "vuln": true, "vulnerability": true, "tech": true,
	"detect": true, "detection": true, "panel": true, "panels": true, "login": true, "cms": true,
	"exposure": true, "exposures": true, "misconfig": true, "misconfiguration": true,
	"rce": true, "lfi": true, "xss": true, "sqli": true, "ssrf": true, "ssti": true,
	"redirect": true, "disclosure": true, "default": true, "auth": true, "bypass": true,
	"injection": true, "traversal": true, "config": true, "files": true, "file": true,
	"backup": true, "takeover": true, "oast": true, "intrusive": true, "unauth": true,
	"router": true, "iot": true, "network": true, "http": true, "json": true, "api": true,
	"server": true, "service": true, "framework": true, "plugin": true, "theme": true,
	"webserver": true, "database": true, "cloud": true, "devops": true, "tools": true,
	"edb": true, "kev": true, "packetstorm": true, "seclists": true, "osint": true,
	// category labels
	"generic": true, "audit": true, "miscellaneous": true, "misc": true, "enumeration": true,
	"vulnerabilities": true, "exposed": true, "keys": true, "secret": true, "secrets": true,
	// platform / OS / cloud-provider tokens (not products)
	"linux": true, "windows": true, "macos": true, "unix": true, "android": true, "ios": true,
	"aws": true, "azure": true, "gcp": true, "alibaba": true, "kubernetes": true, "k8s": true,
	"docker": true, "mobile": true,
	// common English words that collide with product names
	"dashboard": true, "gateway": true, "path": true, "console": true, "firewall": true,
	"monitor": true, "control": true, "permissions": true, "oauth": true, "analytics": true,
	"enterprise": true, "report": true, "reports": true, "help": true, "printer": true,
	"core": true, "commerce": true, "anchor": true, "nova": true, "element": true,
	"webclient": true, "memcached": true, "manager": true, "management": true, "admin": true,
	"client": true, "agent": true, "portal": true, "gateway2": true, "status": true,
	"user": true, "users": true, "account": true, "token": true, "tokens": true,
	"web": true, "app": true, "application": true, "system": true, "platform": true,
}

// normToken lowercases and trims a vendor/product token. CPE uses '_' for
// spaces; we keep it as-is so the id stays stable and machine-joinable.
func normToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// CPE wildcards / NA markers are not real tokens.
	if s == "*" || s == "-" {
		return ""
	}
	// URLs / paths / multi-word strings are not clean product tokens (guards
	// against junk nodes like "https://apisix.apache.org").
	if strings.ContainsAny(s, "/ ") {
		return ""
	}
	return s
}

// techID builds the canonical technology id from vendor/product. When vendor is
// empty or equal to product we collapse to a single token to avoid duplicate
// nodes like "wordpress:wordpress" vs "wordpress".
func techID(vendor, product string) string {
	vendor = normToken(vendor)
	product = normToken(product)
	switch {
	case product == "":
		return ""
	case vendor == "" || vendor == product:
		return product
	default:
		return vendor + ":" + product
	}
}

// aliasesFor returns alias tokens that runtime detection (wappalyzer names,
// tags) might surface for a tech, so they can be reconciled to the canonical id.
// Pillar 1 derives these from product/vendor tokens; AI augments this offline.
func aliasesFor(vendor, product string, tags []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = normToken(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	// Only whole product/vendor tokens are safe aliases. Splitting on separators
	// produces ambiguous fragments (manager, server, token, web, ...) that cause
	// false tag/id reconciliation, so we deliberately avoid it.
	add(product)
	if vendor != product {
		add(vendor)
	}
	return out
}
