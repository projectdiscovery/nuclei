package catalogue

import (
	"bufio"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
)

const nucleiIgnoreFile = ".nuclei-ignore"

// readNucleiIgnoreFile reads the nuclei ignore file marking it in map
func (c *Catalogue) readNucleiIgnoreFile() {
	file, err := os.Open(path.Join(c.templatesDirectory, nucleiIgnoreFile))
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "#") {
			continue
		}
		c.ignoreFiles = append(c.ignoreFiles, text)
	}
}

// checkIfInNucleiIgnore checks if a path falls under nuclei-ignore rules.
func (c *Catalogue) checkIfInNucleiIgnore(item string) bool {
	if c.templatesDirectory == "" {
		return false
	}

	for _, paths := range c.ignoreFiles {
		dir := path.Dir(item)

		if strings.EqualFold(dir, paths) {
			gologger.Error().Msgf("Excluding %s due to nuclei-ignore filter", item)
			return true
		}
		if strings.HasSuffix(paths, ".yaml") && strings.HasSuffix(item, paths) {
			gologger.Error().Msgf("Excluding %s due to nuclei-ignore filter", item)
			return true
		}
	}
	return false
}

// ignoreFilesWithExcludes ignores results with exclude paths
func (c *Catalogue) ignoreFilesWithExcludes(results, excluded []string) []string {
	var templates []string

	for _, result := range results {
		matched := false
		for _, paths := range excluded {
			dir := path.Dir(result)

			if strings.EqualFold(dir, paths) {
				matched = true
				break
			}
			if strings.HasSuffix(paths, ".yaml") && strings.HasSuffix(result, paths) {
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
