package techgraph

import "strings"

// excludedCategories never participate in automatic scan (opt-in/specialized).
var excludedCategories = map[string]struct{}{
	"fuzzing":     {},
	"osint":       {},
	"token-spray": {},
	"malware":     {},
	"cloud":       {},
}

// baselineCategories are the only categories whose product-less templates may be
// considered for the tech-agnostic baseline. Product-specific categories (cves,
// vulnerabilities, exposed-panels, default-logins, cnvd) are intentionally absent:
// an unmappable template there must go to unmapped (fallback), never baseline.
var baselineCategories = map[string]struct{}{
	"exposures":        {},
	"misconfiguration": {},
	"miscellaneous":    {},
	"iot":              {},
	"takeovers":        {}, // subdomain takeover signatures are run host-agnostically
}

// genericBaselineTags positively identify a tech-agnostic check.
var genericBaselineTags = map[string]struct{}{
	"cors": {}, "crlf": {}, "open-redirect": {}, "ds_store": {}, "dsstore": {},
	"phpinfo": {}, "directory-listing": {}, "listing": {}, "debug": {},
	"robots": {}, "sitemap": {}, "git": {}, "svn": {}, "dotenv": {},
	"host-header-injection": {}, "http-trace": {}, "options-method": {},
	"well-known": {}, "trace": {},
}

// genericBaselineIDSubstrings positively identify generic checks by id.
var genericBaselineIDSubstrings = []string{
	"git-config", "gitignore", "git-credentials", "svn-", ".env", "dotenv",
	"phpinfo", "directory-listing", "dir-listing", "ds-store", "ds_store",
	"robots-txt", "sitemap-", "cors-", "crlf-", "open-redirect", "trace-method",
	"options-method", "well-known", "backup-files", "sql-dump",
}

// classifyBaseline decides whether an otherwise-unmapped template is a genuinely
// generic, tech-agnostic baseline check. It is a positive allowlist: anything not
// recognised as generic is left for the caller to mark unmapped.
func classifyBaseline(info templateInfo) (Tier, bool) {
	// tech-agnostic "generic" buckets (e.g. vulnerabilities/generic/* holds
	// cors/sqli/xss probes that apply to any target) qualify regardless of
	// category. The logs/files/backups subdir heuristic was removed: it leaked
	// product-specific exposures (bitrix, magento, oracle-ebs, ...) into baseline.
	if info.Subdir == "generic" {
		return TierThorough, true
	}
	if _, ok := baselineCategories[info.Category]; !ok {
		return "", false
	}
	// takeovers are wholesale host-agnostic.
	if info.Category == "takeovers" {
		return TierBalanced, true
	}
	for _, tag := range info.Tags {
		if _, ok := genericBaselineTags[normToken(tag)]; ok {
			return TierBalanced, true
		}
	}
	idl := strings.ToLower(info.ID)
	for _, sub := range genericBaselineIDSubstrings {
		if strings.Contains(idl, sub) {
			return TierBalanced, true
		}
	}
	return "", false
}
