package loader

import (
	"bufio"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

type ContentType string

const (
	Template ContentType = "Template"
	Workflow ContentType = "Workflow"
)

type RemoteContent struct {
	Content []string
	Type    ContentType
	Error   error
}

func getRemoteTemplatesAndWorkflows(templateURLs, workflowURLs, remoteTemplateDomainList []string) ([]string, []string, error) {
	var (
		err   error
		muErr sync.Mutex
	)
	remoteTemplateList := sliceutil.NewSyncSlice[string]()
	remoteWorkFlowList := sliceutil.NewSyncSlice[string]()

	awg, errAwg := syncutil.New(syncutil.WithSize(50))
	if errAwg != nil {
		return nil, nil, errAwg
	}

	loadItem := func(URL string, contentType ContentType) {
		defer awg.Done()

		remoteContent := getRemoteContent(URL, remoteTemplateDomainList, contentType)
		if remoteContent.Error != nil {
			muErr.Lock()
			if err != nil {
				err = errors.New(remoteContent.Error.Error() + ": " + err.Error())
			} else {
				err = remoteContent.Error
			}
			muErr.Unlock()
		} else {
			switch remoteContent.Type {
			case Template:
				remoteTemplateList.Append(remoteContent.Content...)
			case Workflow:
				remoteWorkFlowList.Append(remoteContent.Content...)
			}
		}
	}

	for _, templateURL := range templateURLs {
		awg.Add()
		go loadItem(templateURL, Template)
	}
	for _, workflowURL := range workflowURLs {
		awg.Add()
		go loadItem(workflowURL, Workflow)
	}

	awg.Wait()

	return remoteTemplateList.Slice, remoteWorkFlowList.Slice, err
}

func getRemoteContent(URL string, remoteTemplateDomainList []string, contentType ContentType) RemoteContent {
	if err := validateRemoteTemplateURL(URL, remoteTemplateDomainList); err != nil {
		return RemoteContent{Error: err}
	}
	if strings.HasPrefix(URL, "http") && stringsutil.HasSuffixAny(URL, extensions.YAML) {
		return RemoteContent{
			Content: []string{URL},
			Type:    contentType,
		}
	}
	response, err := retryablehttp.DefaultClient().Get(URL)
	if err != nil {
		return RemoteContent{Error: err}
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return RemoteContent{Error: fmt.Errorf("get \"%s\": unexpect status %d", URL, response.StatusCode)}
	}

	scanner := bufio.NewScanner(response.Body)
	var templateList []string
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		if utils.IsURL(text) {
			if err := validateRemoteTemplateURL(text, remoteTemplateDomainList); err != nil {
				return RemoteContent{Error: err}
			}
		}
		templateList = append(templateList, text)
	}

	if err := scanner.Err(); err != nil {
		return RemoteContent{Error: errors.Wrap(err, "get \"%s\"")}
	}

	return RemoteContent{
		Content: templateList,
		Type:    contentType,
	}
}

func validateRemoteTemplateURL(inputURL string, remoteTemplateDomainList []string) error {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return err
	}
	if !utils.StringSliceContains(remoteTemplateDomainList, parsedURL.Host) {
		return errors.Errorf("Remote template URL host (%s) is not present in the `remote-template-domain` list in nuclei config", parsedURL.Host)
	}
	return nil
}
