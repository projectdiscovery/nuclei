package loader

import (
	"bufio"
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
	remoteContentChannel := make(chan RemoteContent)

	for _, templateURL := range templateURLs {
		go getRemoteContent(templateURL, remoteTemplateDomainList, remoteContentChannel, Template)
	}
	for _, workflowURL := range workflowURLs {
		go getRemoteContent(workflowURL, remoteTemplateDomainList, remoteContentChannel, Workflow)
	}

	var remoteTemplateList []string
	var remoteWorkFlowList []string
	var err error
	for i := 0; i < (len(templateURLs) + len(workflowURLs)); i++ {
		remoteContent := <-remoteContentChannel
		if remoteContent.Error != nil {
			if err != nil {
				err = errors.New(remoteContent.Error.Error() + ": " + err.Error())
			} else {
				err = remoteContent.Error
			}
		} else {
			if remoteContent.Type == Template {
				remoteTemplateList = append(remoteTemplateList, remoteContent.Content...)
			} else if remoteContent.Type == Workflow {
				remoteWorkFlowList = append(remoteWorkFlowList, remoteContent.Content...)
			}
		}
	}
	return remoteTemplateList, remoteWorkFlowList, err
}

func getRemoteContent(URL string, remoteTemplateDomainList []string, remoteContentChannel chan<- RemoteContent, contentType ContentType) {
	if err := validateRemoteTemplateURL(URL, remoteTemplateDomainList); err != nil {
		remoteContentChannel <- RemoteContent{
			Error: err,
		}
		return
	}
	if strings.HasPrefix(URL, "http") && stringsutil.HasSuffixAny(URL, extensions.YAML) {
		remoteContentChannel <- RemoteContent{
			Content: []string{URL},
			Type:    contentType,
		}
		return
	}
	response, err := retryablehttp.DefaultClient().Get(URL)
	if err != nil {
		remoteContentChannel <- RemoteContent{
			Error: err,
		}
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		remoteContentChannel <- RemoteContent{
			Error: fmt.Errorf("get \"%s\": unexpect status %d", URL, response.StatusCode),
		}
		return
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
				remoteContentChannel <- RemoteContent{
					Error: err,
				}
				return
			}
		}
		templateList = append(templateList, text)
	}

	if err := scanner.Err(); err != nil {
		remoteContentChannel <- RemoteContent{
			Error: errors.Wrap(err, "get \"%s\""),
		}
		return
	}

	remoteContentChannel <- RemoteContent{
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
