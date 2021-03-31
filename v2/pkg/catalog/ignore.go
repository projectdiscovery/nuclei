package catalog

import (
	"strings"

	"github.com/projectdiscovery/gologger"
)

// checkIfInNucleiIgnore checks if a path falls under nuclei-ignore rules.
func (c *Catalog) checkIfInNucleiIgnore(item string) bool {
	if c.templatesDirectory == "" {
		return false
	}

	matched := false
	for _, paths := range c.ignoreFiles {
		if !strings.HasSuffix(paths, ".yaml") {
			if strings.HasSuffix(strings.TrimSuffix(item, "/"), strings.TrimSuffix(paths, "/")) {
				matched = true
				break
			}
		} else if strings.HasSuffix(item, paths) {
			matched = true
			break
		}
	}
	if matched {
		gologger.Error().Msgf("Excluding %s due to nuclei-ignore filter", item)
		return true
	}
	return false
}

// ignoreFilesWithExcludes ignores results with exclude paths
func (c *Catalog) ignoreFilesWithExcludes(results, excluded []string) []string {
	var templates []string

	for _, result := range results {
		matched := false
		for _, paths := range excluded {
			if !strings.HasSuffix(paths, ".yaml") {
				if strings.HasSuffix(strings.TrimSuffix(result, "/"), strings.TrimSuffix(paths, "/")) {
					matched = true
					break
				}
			} else if strings.HasSuffix(result, paths) {
				matched = true
				break
			}
		}
		if !matched {
			templates = append(templates, result)
		} else {
			gologger.Error().Msgf("Excluding %s due to excludes filter", result)
		}
	}
	return templates
}
