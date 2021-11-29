package templates

import (
	"fmt"

	"github.com/rs/xid"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapsutil"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
)

// Cluster clusters a list of templates into a lesser number if possible based
// on the similarity between the sent requests.
//
// If the attributes match, multiple requests can be clustered into a single
// request which saves time and network resources during execution.
func Cluster(list map[string]*Template) [][]*Template {
	final := [][]*Template{}

	// Each protocol that can be clustered should be handled here.
	for key, template := range list {
		// We only cluster http requests as of now.
		// Take care of requests that can't be clustered first.
		if len(template.RequestsHTTP) == 0 {
			delete(list, key)
			final = append(final, []*Template{template})
			continue
		}

		delete(list, key) // delete element first so it's not found later.
		// Find any/all similar matching request that is identical to
		// this one and cluster them together for http protocol only.
		if len(template.RequestsHTTP) == 1 {
			cluster := []*Template{}

			for otherKey, other := range list {
				if len(other.RequestsHTTP) == 0 {
					continue
				}
				if template.RequestsHTTP[0].CanCluster(other.RequestsHTTP[0]) {
					delete(list, otherKey)
					cluster = append(cluster, other)
				}
			}
			if len(cluster) > 0 {
				cluster = append(cluster, template)
				final = append(final, cluster)
				continue
			}
		}
		final = append(final, []*Template{template})
	}
	return final
}

func ClusterTemplates(templatesList []*Template, options protocols.ExecuterOptions) ([]*Template, int) {
	if options.Options.OfflineHTTP {
		return templatesList, 0
	}

	templatesMap := make(map[string]*Template)
	for _, v := range templatesList {
		templatesMap[v.Path] = v
	}
	clusterCount := 0

	finalTemplatesList := make([]*Template, 0, len(templatesList))
	clusters := Cluster(templatesMap)
	for _, cluster := range clusters {
		if len(cluster) > 1 {
			executerOpts := options

			clusterID := fmt.Sprintf("cluster-%s", xid.New().String())

			finalTemplatesList = append(finalTemplatesList, &Template{
				ID:            clusterID,
				RequestsHTTP:  cluster[0].RequestsHTTP,
				Executer:      NewExecuter(cluster, &executerOpts),
				TotalRequests: len(cluster[0].RequestsHTTP),
			})
			clusterCount += len(cluster)
		} else {
			finalTemplatesList = append(finalTemplatesList, cluster...)
		}
	}
	return finalTemplatesList, clusterCount
}

// Executer executes a group of requests for a protocol for a clustered
// request. It is different from normal executers since the original
// operators are all combined and post processed after making the request.
//
// TODO: We only cluster http requests as of now.
type Executer struct {
	requests  *http.Request
	operators []*clusteredOperator
	options   *protocols.ExecuterOptions
}

type clusteredOperator struct {
	templateID   string
	templatePath string
	templateInfo model.Info
	operator     *operators.Operators
}

var _ protocols.Executer = &Executer{}

// NewExecuter creates a new request executer for list of requests
func NewExecuter(requests []*Template, options *protocols.ExecuterOptions) *Executer {
	executer := &Executer{
		options:  options,
		requests: requests[0].RequestsHTTP[0],
	}
	for _, req := range requests {
		executer.operators = append(executer.operators, &clusteredOperator{
			templateID:   req.ID,
			templateInfo: req.Info,
			templatePath: req.Path,
			operator:     req.RequestsHTTP[0].CompiledOperators,
		})
	}
	return executer
}

// Compile compiles the execution generators preparing any requests possible.
func (e *Executer) Compile() error {
	return e.requests.Compile(e.options)
}

// Requests returns the total number of requests the rule will perform
func (e *Executer) Requests() int {
	var count int
	count += e.requests.Requests()
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *Executer) Execute(input string, params map[string]interface{}) (bool, error) {
	var results bool

	previous := make(map[string]interface{})
	dynamicValues := make(map[string]interface{})
	dynamicValues = mapsutil.MergeMaps(dynamicValues, params)
	err := e.requests.ExecuteWithResults(input, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
		for _, operator := range e.operators {
			result, matched := operator.operator.Execute(event.InternalEvent, e.requests.Match, e.requests.Extract, e.options.Options.Debug || e.options.Options.DebugResponse)
			event.InternalEvent["template-id"] = operator.templateID
			event.InternalEvent["template-path"] = operator.templatePath
			event.InternalEvent["template-info"] = operator.templateInfo

			if result == nil && !matched {
				if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
					gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
				}
				continue
			}
			if matched && result != nil {
				event.OperatorsResult = result
				event.Results = e.requests.MakeResultEvent(event)
				results = true

				_ = writer.WriteResult(event, e.options.Output, e.options.Progress, e.options.IssuesClient)
			}
		}
	})
	if err != nil && e.options.HostErrorsCache != nil && e.options.HostErrorsCache.CheckError(err) {
		e.options.HostErrorsCache.MarkFailed(input)
	}
	return results, err
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *Executer) ExecuteWithResults(input string, params map[string]interface{}, callback protocols.OutputEventCallback) error {
	dynamicValues := make(map[string]interface{})
	err := e.requests.ExecuteWithResults(input, dynamicValues, nil, func(event *output.InternalWrappedEvent) {
		for _, operator := range e.operators {
			result, matched := operator.operator.Execute(event.InternalEvent, e.requests.Match, e.requests.Extract, e.options.Options.Debug || e.options.Options.DebugResponse)
			if matched && result != nil {
				event.OperatorsResult = result
				event.InternalEvent["template-id"] = operator.templateID
				event.InternalEvent["template-path"] = operator.templatePath
				event.InternalEvent["template-info"] = operator.templateInfo
				event.Results = e.requests.MakeResultEvent(event)
				callback(event)
			}
		}
	})
	if err != nil && e.options.HostErrorsCache != nil && e.options.HostErrorsCache.CheckError(err) {
		e.options.HostErrorsCache.MarkFailed(input)
	}
	return err
}
