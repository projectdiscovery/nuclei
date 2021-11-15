package loader

import (
	"bufio"
	"fmt"
	"net/http"
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

func getRemoteTemplatesAndWorkflows(templateURLs []string, workflowURLs []string) ([]string, []string, error) {
	remoteContentErrorChannel := make(chan RemoteContentError)

	for _, templateURL := range templateURLs {
		go getRemoteContent(templateURL, remoteContentErrorChannel, Template)
	}
	for _, workflowURL := range workflowURLs {
		go getRemoteContent(workflowURL, remoteContentErrorChannel, Workflow)
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

func getRemoteContent(URL string, w chan<- RemoteContentError, contentType ContentType) {
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
