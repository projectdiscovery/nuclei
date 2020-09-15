package catalogue

import (
	"bufio"
	"os"
	"path"
	"strings"
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
		c.ignoreFiles = append(c.ignoreFiles, text)
	}
}

// checkIfInNucleiIgnore checks if a path falls under nuclei-ignore rules.
func (c *Catalogue) checkIfInNucleiIgnore(item string) bool {
	if c.templatesDirectory == "" {
		return false
	}

	for _, paths := range c.ignoreFiles {
		// If we have a path to ignore, check if it's in the item.
		if paths[len(paths)-1] == '/' {
			if strings.Contains(item, paths) {
				return true
			}

			continue
		}
		// Check for file based extension in ignores
		if strings.HasSuffix(item, paths) {
			return true
		}
	}
	return false
}

// ignoreFilesWithExcludes ignores results with exclude paths
func (c *Catalogue) ignoreFilesWithExcludes(results, excluded []string) []string {
	excludeMap := make(map[string]struct{}, len(excluded))
	for _, excl := range excluded {
		excludeMap[excl] = struct{}{}
	}

	templates := make([]string, 0, len(results))
	for _, incl := range results {
		if _, found := excludeMap[incl]; !found {
			templates = append(templates, incl)
		}
	}
	return templates
}
