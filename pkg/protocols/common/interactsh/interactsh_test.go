package interactsh

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	serverint "github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestProcessInteractionForRequestConcurrentEventUpdate(t *testing.T) {
	const (
		keyCount        = 4096
		expressionCount = 256
		mutationCount   = keyCount * 200
	)

	eventData := make(output.InternalEvent, keyCount+2)
	eventData[templateIdAttribute] = "test-template"
	eventData["host"] = "example.com"

	var expressionBuilder strings.Builder
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key%d", i)
		eventData[key] = fmt.Sprintf("value%d", i)
		if i < expressionCount {
			expressionBuilder.WriteString("{{")
			expressionBuilder.WriteString(key)
			expressionBuilder.WriteString("}}")
		}
	}

	matcher := &matchers.Matcher{
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Words: []string{expressionBuilder.String()},
	}
	op := &operators.Operators{
		Matchers:          []*matchers.Matcher{matcher},
		MatchersCondition: "or",
	}
	require.NoError(t, op.Compile())

	var startWriter sync.Once
	writerStarted := make(chan struct{})
	requestData := &RequestData{
		Event:     &output.InternalWrappedEvent{InternalEvent: eventData},
		Operators: op,
		MatchFunc: func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
			startWriter.Do(func() {
				close(writerStarted)
			})
			runtime.Gosched()
			return matcher.MatchWords("not-present-in-corpus", data)
		},
		ExtractFunc: func(map[string]interface{}, *extractors.Extractor) map[string]struct{} {
			return nil
		},
	}

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		<-writerStarted
		for i := 0; i < mutationCount; i++ {
			key := fmt.Sprintf("key%d", i%keyCount)
			requestData.Event.Lock()
			requestData.Event.InternalEvent[key] = fmt.Sprintf("mutated-%d", i)
			if i%17 == 0 {
				delete(requestData.Event.InternalEvent, key)
				requestData.Event.InternalEvent[key] = fmt.Sprintf("mutated-%d", i)
			}
			requestData.Event.Unlock()
		}
	}()

	client := &Client{options: &Options{}}
	matched := client.processInteractionForRequest(&serverint.Interaction{
		Protocol:      "dns",
		RawRequest:    "request",
		RawResponse:   "response",
		RemoteAddress: "127.0.0.1",
	}, requestData)
	writerWG.Wait()

	require.False(t, matched)
}
