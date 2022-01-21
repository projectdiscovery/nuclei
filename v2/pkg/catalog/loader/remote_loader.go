package loader

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type ContentType string

const (
	Template ContentType = "Template"
	Workflow ContentType = "Workflow"
)

type RemoteContentError struct {
	Content []string
	Type    ContentType
	Error   error
}

func getRemoteTemplatesAndWorkflows(templateURLs, workflowURLs, remoteTemplateDomainList []string) ([]string, []string, error) {
	remoteContentErrorChannel := make(chan RemoteContentError)

	for _, templateURL := range templateURLs {
		go getRemoteContent(templateURL, remoteTemplateDomainList, remoteContentErrorChannel, Template)
	}
	for _, workflowURL := range workflowURLs {
		go getRemoteContent(workflowURL, remoteTemplateDomainList, remoteContentErrorChannel, Workflow)
	}

	var remoteTemplateList []string
	var remoteWorkFlowList []string
	var err error
	for i := 0; i < (len(templateURLs) + len(workflowURLs)); i++ {
		remoteContentError := <-remoteContentErrorChannel
		if remoteContentError.Error != nil {
			if err != nil {
				err = errors.New(remoteContentError.Error.Error() + ": " + err.Error())
			} else {
				err = remoteContentError.Error
			}
		} else {
			if remoteContentError.Type == Template {
				remoteTemplateList = append(remoteTemplateList, remoteContentError.Content...)
			} else if remoteContentError.Type == Workflow {
				remoteWorkFlowList = append(remoteWorkFlowList, remoteContentError.Content...)
			}
		}
	}

	return remoteTemplateList, remoteWorkFlowList, err
}

func getRemoteContent(URL string, remoteTemplateDomainList []string, w chan<- RemoteContentError, contentType ContentType) {
	if strings.HasPrefix(URL, "http") && (strings.HasSuffix(URL, ".yaml") || strings.HasSuffix(URL, ".yml")) {
		parsed, err := url.Parse(URL)
		if err != nil {
			w <- RemoteContentError{
				Error: err,
			}
			return
		}
		if !stringSliceContains(remoteTemplateDomainList, parsed.Host) {
			w <- RemoteContentError{
				Error: errors.Errorf("Remote template URL host (%s) is not present in the `remote-template-domain` list in nuclei config", parsed.Host),
			}
			return
		}
		w <- RemoteContentError{
			Content: []string{URL},
			Type:    contentType,
		}
		return
	}
	response, err := http.Get(URL)
	if err != nil {
		w <- RemoteContentError{
			Error: err,
		}
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		w <- RemoteContentError{
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
		templateList = append(templateList, text)
	}

	if err := scanner.Err(); err != nil {
		w <- RemoteContentError{
			Error: errors.Wrap(err, "get \"%s\""),
		}
		return
	}

	w <- RemoteContentError{
		Content: templateList,
		Type:    contentType,
	}
}

func stringSliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}
