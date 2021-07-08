package load

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"gopkg.in/yaml.v2"
)

// Load loads a template by parsing metadata and running
// all tag and path based filters on the template.
func Load(templatePath string, workflow bool, customTags []string, tagFilter *filter.TagFilter) (bool, error) {
	f, err := os.Open(templatePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return false, err
	}

	template := make(map[string]interface{})
	err = yaml.NewDecoder(bytes.NewReader(data)).Decode(template)
	if err != nil {
		return false, err
	}

	info, ok := template["info"]
	if !ok {
		return false, errors.New("no template info field provided")
	}
	infoMap, ok := info.(map[interface{}]interface{})
	if !ok {
		return false, errors.New("could not get info")
	}

	if _, nameOk := infoMap["name"]; !nameOk {
		return false, errors.New("no template name field provided")
	}
	author, ok := infoMap["author"]
	if !ok {
		return false, errors.New("no template author field provided")
	}
	severity, ok := infoMap["severity"]
	if !ok {
		severity = ""
	}

	templateTags, ok := infoMap["tags"]
	if !ok {
		templateTags = ""
	}
	tagStr := types.ToString(templateTags)

	tags := strings.Split(tagStr, ",")
	severityStr := strings.ToLower(types.ToString(severity))
	authors := strings.Split(types.ToString(author), ",")

	matched := false

	_, workflowsFound := template["workflows"]
	if !workflowsFound && workflow {
		return false, nil
	}
	if workflow {
		return true, nil
	}
	for _, tag := range tags {
		for _, author := range authors {
			var match bool
			var err error

			if len(customTags) == 0 {
				match, err = tagFilter.Match(strings.ToLower(strings.TrimSpace(tag)), strings.ToLower(strings.TrimSpace(author)), severityStr)
			} else {
				match, err = tagFilter.MatchWithAllowedTags(customTags, strings.ToLower(strings.TrimSpace(tag)), strings.ToLower(strings.TrimSpace(author)), severityStr)
			}
			if err == filter.ErrExcluded {
				return false, filter.ErrExcluded
			}
			if !matched && match {
				matched = true
			}
		}
	}
	if !matched {
		return false, nil
	}
	if workflowsFound && !workflow {
		return false, nil
	}
	return true, nil
}
