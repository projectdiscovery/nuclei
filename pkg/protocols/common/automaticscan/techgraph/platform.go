package techgraph

// platforms are technologies with large plugin/extension ecosystems whose
// add-on templates carry the add-on as `product` (often with the platform as
// `vendor` or only as a tag). Runtime detection sees the platform, not each
// plugin, so those templates must be reachable from the platform node.
var platforms = map[string]string{
	"wordpress":  "wordpress",
	"joomla":     "joomla",
	"drupal":     "drupal",
	"magento":    "magento",
	"prestashop": "prestashop",
	"opencart":   "opencart",
	"moodle":     "moodle",
	"typo3":      "typo3",
	"dotnetnuke": "dotnetnuke",
	"concrete5":  "concrete5",
	"shopware":   "shopware",
	"vbulletin":  "vbulletin",
	"mybb":       "mybb",
	"phpbb":      "phpbb",
}

// platformTagAliases maps secondary tag tokens to a platform key.
var platformTagAliases = map[string]string{
	"wp":        "wordpress",
	"wp-plugin": "wordpress",
	"wp-theme":  "wordpress",
}

// detectPlatform returns the platform node id when a template belongs to a
// platform's add-on ecosystem (and is not the platform core itself).
func detectPlatform(info templateInfo) (string, bool) {
	vendor := normToken(info.Vendor)
	product := normToken(info.Product)

	if p, ok := platforms[vendor]; ok && product != "" && product != p {
		return p, true
	}
	for _, tag := range info.Tags {
		t := normToken(tag)
		if p, ok := platforms[t]; ok {
			if product != "" && product != p {
				return p, true
			}
		}
		if p, ok := platformTagAliases[t]; ok {
			if product != p {
				return p, true
			}
		}
	}
	return "", false
}

// isDetection reports whether a template is a phase-1 detector.
func isDetection(info templateInfo) bool {
	for _, tag := range info.Tags {
		switch normToken(tag) {
		case "tech", "detect", "favicon":
			return true
		}
	}
	return false
}

// isDetectionSeverity guards the detection bucket against vuln/exposure templates
// that merely carry a "tech"/"detect" tag. Real fingerprint templates are
// informational; medium+ severity indicates an actual finding, not detection.
func isDetectionSeverity(info templateInfo) bool {
	switch info.Severity {
	case "", "info", "low":
		return true
	default:
		return false
	}
}
