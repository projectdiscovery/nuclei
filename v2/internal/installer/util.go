package installer

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// GetNewTemplatesInVersions returns templates path of all newly added templates
// in these versions
func GetNewTemplatesInVersions(versions ...string) []string {
	allTemplates := []string{}
	for _, v := range versions {
		if v == config.DefaultConfig.TemplateVersion {
			allTemplates = append(allTemplates, config.DefaultConfig.GetNewAdditions()...)
		}
		_, err := semver.NewVersion(v)
		if err != nil {
			gologger.Error().Msgf("%v is not a valid semver version. skipping", v)
			continue
		}
		if config.IsOutdatedVersion(v, "v8.8.4") {
			// .new-additions was added in v8.8.4 any version before that is not supported
			gologger.Error().Msgf(".new-additions support was added in v8.8.4 older versions are not supported")
			continue
		}

		arr, err := getNewAdditionsFileFromGitHub(v)
		if err != nil {
			gologger.Error().Msgf("failed to fetch new additions for %v got: %v", v, err)
			continue
		}
		allTemplates = append(allTemplates, arr...)
	}
	return allTemplates
}

func getNewAdditionsFileFromGitHub(version string) ([]string, error) {
	resp, err := retryableHttpClient.Get(fmt.Sprintf("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/%s/.new-additions", version))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errorutil.New("version not found")
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	templatesList := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		if config.IsTemplate(text) {
			templatesList = append(templatesList, text)
		}
	}
	return templatesList, nil
}

func PurgeEmptyDirectories(dir string) {
	alldirs := []string{}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			alldirs = append(alldirs, path)
		}
		return nil
	})
	// sort in ascending order
	sort.Strings(alldirs)
	// reverse the order
	sort.Sort(sort.Reverse(sort.StringSlice(alldirs)))

	for _, d := range alldirs {
		if isEmptyDir(d) {
			_ = os.RemoveAll(d)
		}
	}
}

func isEmptyDir(dir string) bool {
	hasFiles := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			hasFiles = true
			return io.EOF
		}
		return nil
	})
	return !hasFiles
}

// getUtmSource returns utm_source from environment variable
func getUtmSource() string {
	value := ""
	switch {
	case os.Getenv("GH_ACTION") != "":
		value = "ghci"
	case os.Getenv("TRAVIS") != "":
		value = "travis"
	case os.Getenv("CIRCLECI") != "":
		value = "circleci"
	case os.Getenv("CI") != "":
		value = "gitlabci" // this also includes bitbucket
	case os.Getenv("GITHUB_ACTIONS") != "":
		value = "ghci"
	case os.Getenv("AWS_EXECUTION_ENV") != "":
		value = os.Getenv("AWS_EXECUTION_ENV")
	case os.Getenv("JENKINS_URL") != "":
		value = "jenkins"
	case os.Getenv("FUNCTION_TARGET") != "":
		value = "gcf"
	default:
		value = "unknown"
	}
	return value
}
