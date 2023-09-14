package templates

import (
	"fmt"
	"sort"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	cryptoutil "github.com/projectdiscovery/utils/crypto"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Cluster clusters a list of templates into a lesser number if possible based
// on the similarity between the sent requests.
//
// If the attributes match, multiple requests can be clustered into a single
// request which saves time and network resources during execution.
//
// The clusterer goes through all the templates, looking for templates with a single
// HTTP/DNS/TLS request to an endpoint (multiple requests aren't clustered as of now).
//
// All the templates are iterated and any templates with request that is identical
// to the first individual request is compared for equality.
// The equality check is performed as described below -
//
// Cases where clustering is not performed (request is considered different)
//   - If request contains payloads,raw,body,unsafe,req-condition,name attributes
//   - If request methods,max-redirects,cookie-reuse,redirects are not equal
//   - If request paths aren't identical.
//   - If request headers aren't identical
//   - Similarly for DNS, only identical DNS requests are clustered to a target.
//   - Similarly for TLS, only identical TLS requests are clustered to a target.
//
// If multiple requests are identified as identical, they are appended to a slice.
// Finally, the engine creates a single executer with a clusteredexecuter for all templates
// in a cluster.
func Cluster(list []*Template) [][]*Template {
	final := [][]*Template{}
	skip := mapsutil.NewSyncLockMap[string, struct{}]()

	for _, template := range list {
		key := template.Path

		if skip.Has(key) {
			continue
		}

		// We only cluster http, dns and ssl requests as of now.
		// Take care of requests that can't be clustered first.
		if len(template.RequestsHTTP) == 0 && len(template.RequestsDNS) == 0 && len(template.RequestsSSL) == 0 {
			_ = skip.Set(key, struct{}{})
			final = append(final, []*Template{template})
			continue
		}
		_ = skip.Set(key, struct{}{})

		var templateType types.ProtocolType
		switch {
		case len(template.RequestsDNS) == 1:
			templateType = types.DNSProtocol
		case len(template.RequestsHTTP) == 1:
			templateType = types.HTTPProtocol
		case len(template.RequestsSSL) == 1:
			templateType = types.SSLProtocol
		}

		// Find any/all similar matching request that is identical to
		// this one and cluster them together for http protocol only.
		cluster := []*Template{}
		for _, other := range list {
			otherKey := other.Path

			if skip.Has(otherKey) {
				continue
			}

			switch templateType {
			case types.DNSProtocol:
				if len(other.RequestsDNS) != 1 {
					continue
				} else if template.RequestsDNS[0].CanCluster(other.RequestsDNS[0]) {
					_ = skip.Set(otherKey, struct{}{})
					cluster = append(cluster, other)
				}
			case types.HTTPProtocol:
				if len(other.RequestsHTTP) != 1 {
					continue
				} else if template.RequestsHTTP[0].CanCluster(other.RequestsHTTP[0]) {
					_ = skip.Set(otherKey, struct{}{})
					cluster = append(cluster, other)
				}
			case types.SSLProtocol:
				if len(other.RequestsSSL) != 1 {
					continue
				} else if template.RequestsSSL[0].CanCluster(other.RequestsSSL[0]) {
					_ = skip.Set(otherKey, struct{}{})
					cluster = append(cluster, other)
				}
			}
		}
		if len(cluster) > 0 {
			cluster = append(cluster, template)
			final = append(final, cluster)
		} else {
			final = append(final, []*Template{template})
		}
	}
	return final
}

// ClusterID transforms clusterization into a mathematical hash repeatable across executions with the same templates
func ClusterID(templates []*Template) string {
	allIDS := make([]string, len(templates))
	for tplIndex, tpl := range templates {
		allIDS[tplIndex] = tpl.ID
	}
	sort.Strings(allIDS)
	ids := strings.Join(allIDS, ",")
	return cryptoutil.SHA256Sum(ids)
}

func ClusterTemplates(templatesList []*Template, options protocols.ExecutorOptions) ([]*Template, int) {
	if options.Options.OfflineHTTP || options.Options.DisableClustering {
		return templatesList, 0
	}

	var clusterCount int

	finalTemplatesList := make([]*Template, 0, len(templatesList))
	clusters := Cluster(templatesList)
	for _, cluster := range clusters {
		if len(cluster) > 1 {
			executerOpts := options
			clusterID := fmt.Sprintf("cluster-%s", ClusterID(cluster))

			for _, req := range cluster[0].RequestsDNS {
				req.Options().TemplateID = clusterID
			}
			for _, req := range cluster[0].RequestsHTTP {
				req.Options().TemplateID = clusterID
			}
			for _, req := range cluster[0].RequestsSSL {
				req.Options().TemplateID = clusterID
			}
			executerOpts.TemplateID = clusterID
			finalTemplatesList = append(finalTemplatesList, &Template{
				ID:            clusterID,
				RequestsDNS:   cluster[0].RequestsDNS,
				RequestsHTTP:  cluster[0].RequestsHTTP,
				RequestsSSL:   cluster[0].RequestsSSL,
				Executer:      NewClusterExecuter(cluster, &executerOpts),
				TotalRequests: len(cluster[0].RequestsHTTP) + len(cluster[0].RequestsDNS),
			})
			clusterCount += len(cluster)
		} else {
			finalTemplatesList = append(finalTemplatesList, cluster...)
		}
	}
	return finalTemplatesList, clusterCount
}

// ClusterExecuter executes a group of requests for a protocol for a clustered
// request. It is different from normal executers since the original
// operators are all combined and post processed after making the request.
type ClusterExecuter struct {
	requests     protocols.Request
	operators    []*clusteredOperator
	templateType types.ProtocolType
	options      *protocols.ExecutorOptions
}

type clusteredOperator struct {
	templateID   string
	templatePath string
	templateInfo model.Info
	operator     *operators.Operators
}

var _ protocols.Executer = &ClusterExecuter{}

// NewClusterExecuter creates a new request executer for list of requests
func NewClusterExecuter(requests []*Template, options *protocols.ExecutorOptions) *ClusterExecuter {
	executer := &ClusterExecuter{options: options}
	if len(requests[0].RequestsDNS) == 1 {
		executer.templateType = types.DNSProtocol
		executer.requests = requests[0].RequestsDNS[0]
	} else if len(requests[0].RequestsHTTP) == 1 {
		executer.templateType = types.HTTPProtocol
		executer.requests = requests[0].RequestsHTTP[0]
	} else if len(requests[0].RequestsSSL) == 1 {
		executer.templateType = types.SSLProtocol
		executer.requests = requests[0].RequestsSSL[0]
	}
	appendOperator := func(req *Template, operator *operators.Operators) {
		operator.TemplateID = req.ID
		operator.ExcludeMatchers = options.ExcludeMatchers

		executer.operators = append(executer.operators, &clusteredOperator{
			operator:     operator,
			templateID:   req.ID,
			templateInfo: req.Info,
			templatePath: req.Path,
		})
	}
	for _, req := range requests {
		if executer.templateType == types.DNSProtocol {
			if req.RequestsDNS[0].CompiledOperators != nil {
				appendOperator(req, req.RequestsDNS[0].CompiledOperators)
			}
		} else if executer.templateType == types.HTTPProtocol {
			if req.RequestsHTTP[0].CompiledOperators != nil {
				appendOperator(req, req.RequestsHTTP[0].CompiledOperators)
			}
		} else if executer.templateType == types.SSLProtocol {
			if req.RequestsSSL[0].CompiledOperators != nil {
				appendOperator(req, req.RequestsSSL[0].CompiledOperators)
			}
		}
	}
	return executer
}

// Compile compiles the execution generators preparing any requests possible.
func (e *ClusterExecuter) Compile() error {
	return e.requests.Compile(e.options)
}

// Requests returns the total number of requests the rule will perform
func (e *ClusterExecuter) Requests() int {
	var count int
	count += e.requests.Requests()
	return count
}

// Execute executes the protocol group and returns true or false if results were found.
func (e *ClusterExecuter) Execute(input *contextargs.Context) (bool, error) {
	var results bool

	inputItem := input.Clone()
	if e.options.InputHelper != nil && input.MetaInput.Input != "" {
		if inputItem.MetaInput.Input = e.options.InputHelper.Transform(input.MetaInput.Input, e.templateType); input.MetaInput.Input == "" {
			return false, nil
		}
	}
	previous := make(map[string]interface{})
	dynamicValues := make(map[string]interface{})
	err := e.requests.ExecuteWithResults(inputItem, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
		for _, operator := range e.operators {
			result, matched := operator.operator.Execute(event.InternalEvent, e.requests.Match, e.requests.Extract, e.options.Options.Debug || e.options.Options.DebugResponse)
			event.InternalEvent["template-id"] = operator.templateID
			event.InternalEvent["template-path"] = operator.templatePath
			event.InternalEvent["template-info"] = operator.templateInfo

			if result == nil && !matched && e.options.Options.MatcherStatus {
				if err := e.options.Output.WriteFailure(event); err != nil {
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
	if err != nil && e.options.HostErrorsCache != nil {
		e.options.HostErrorsCache.MarkFailed(input.MetaInput.Input, err)
	}
	return results, err
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (e *ClusterExecuter) ExecuteWithResults(input *contextargs.Context, callback protocols.OutputEventCallback) error {
	dynamicValues := make(map[string]interface{})

	inputItem := input.Clone()
	if e.options.InputHelper != nil && input.MetaInput.Input != "" {
		if inputItem.MetaInput.Input = e.options.InputHelper.Transform(input.MetaInput.Input, e.templateType); input.MetaInput.Input == "" {
			return nil
		}
	}
	err := e.requests.ExecuteWithResults(inputItem, dynamicValues, nil, func(event *output.InternalWrappedEvent) {
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
	if err != nil && e.options.HostErrorsCache != nil {
		e.options.HostErrorsCache.MarkFailed(input.MetaInput.Input, err)
	}
	return err
}
