package core

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// PlanEntry is one unit of work a scan runs: a template, a cluster of
// templates sharing one request, or a workflow, on one target.
type PlanEntry struct {
	// ID identifies the entry across runs of the same plan.
	ID string `json:"id"`
	// Target is empty for self-contained templates, which run once.
	Target string `json:"target,omitempty"`
	// IP is the address the target is pinned to, when it is.
	IP        string   `json:"ip,omitempty"`
	Templates []string `json:"templates"`
	Protocol  string   `json:"protocol"`
	// Requests is what the templates declare, the count -stats starts from.
	// The scan sends fewer when a request needs a value the target lacks,
	// such as {{DN}} on an ip.
	Requests int `json:"requests"`
	// Cost is Requests weighted by how long one request of the protocol
	// takes, in http requests.
	Cost int `json:"cost"`
	// Dynamic marks entries whose requests depend on responses: workflows
	// (only the root is counted), flows and fuzzing.
	Dynamic bool `json:"dynamic,omitempty"`
	// AlternativeTo is the id of an entry running the same origin-scoped
	// template on the same origin. Workers race for an origin, so the scan
	// runs whichever of the group claims it first, and another only when
	// that run fails. Totals count the group once.
	AlternativeTo string `json:"alternative-to,omitempty"`
}

// Plan reports the work ExecuteScanWithOpts would do with the same arguments,
// without sending anything. It applies the same clustering, per-target
// profiles and once-per-origin rule, so a pair is listed only if the scan
// would run it. Later targets of an origin-scoped template are listed as
// alternatives to the first, since the scan retries them when a run fails.
func (e *Engine) Plan(templatesList []*templates.Template, target provider.InputProvider, noCluster bool, emit func(PlanEntry)) {
	finalTemplates, _ := e.clusterTemplates(templatesList, noCluster)
	// clustering does not keep an order; a plan is diffed and edited, so it does
	finalTemplates = slices.SortedFunc(slices.Values(finalTemplates), func(a, b *templates.Template) int {
		return strings.Compare(a.ID, b.ID)
	})

	var targetBound []*templates.Template
	for _, template := range finalTemplates {
		if template.SelfContained {
			emit(withPlanID(planEntry(template, &contextargs.MetaInput{}, nil)))
		} else {
			targetBound = append(targetBound, template)
		}
	}

	// entries are emitted as they are planned, so memory does not grow with
	// the plan; only the first id per origin is kept
	originIDs := make(map[string]string)
	target.Iterate(func(value *contextargs.MetaInput) bool {
		selection := e.selectionFor(value)
		for _, template := range targetBound {
			if selection != nil && !template.SelectedBy(selection) {
				continue
			}
			entry := withPlanID(planEntry(template, value, selection))
			if key, scoped := originScopeKey(template, value); scoped {
				if id, seen := originIDs[key]; seen {
					entry.AlternativeTo = id
				} else {
					originIDs[key] = entry.ID
				}
			}
			emit(entry)
		}
		return true
	})
}

func withPlanID(entry PlanEntry) PlanEntry {
	entry.ID = planEntryID(entry)
	return entry
}

// protocolCost is how many http requests one request of a protocol is worth
// in time. Measured per call against a CDN-fronted site, where an http
// request took about 15ms: a javascript call adds about 150ms of runtime, a
// headless page load with waitload took about 1s. Unlisted protocols cost
// about one round trip, like http.
var protocolCost = map[types.ProtocolType]int{
	types.JavascriptProtocol: 10,
	types.HeadlessProtocol:   60,
}

func planEntry(template *templates.Template, value *contextargs.MetaInput, selection protocols.TemplateSelection) PlanEntry {
	entry := PlanEntry{
		Target:    value.Input,
		IP:        value.CustomIP,
		Templates: []string{template.ID},
		Protocol:  template.Type().String(),
		Requests:  template.TotalRequests,
		Dynamic:   template.Flow != "" || template.IsFuzzableRequest(),
	}
	weight := func(protocol types.ProtocolType) int { return max(protocolCost[protocol], 1) }

	switch {
	case template.CompiledWorkflow != nil:
		// only the root of a workflow is certain to run; subtemplates depend
		// on what it matches
		entry.Requests = 0
		for _, workflow := range template.CompiledWorkflow.Workflows {
			for _, executer := range workflow.Executers {
				requests := executer.Executer.Requests()
				entry.Requests += requests
				entry.Cost += requests * weight(executer.TemplateType)
			}
		}
		entry.Dynamic = true
	case isCluster(template):
		cluster := template.Executer.(*templates.ClusterExecuter)
		entry.Templates = slices.Sorted(slices.Values(cluster.TemplateIDs(selection)))
		// TotalRequests of a cluster counts only its http and dns requests,
		// so an ssl cluster would show none
		entry.Requests = cluster.Requests()
		entry.Cost = entry.Requests * weight(template.Type())
	case len(template.RequestsQueue) > 0:
		// each block is weighted by its own protocol, so a template mixing
		// http with javascript is not priced as all http
		for _, request := range template.RequestsQueue {
			entry.Cost += request.Requests() * weight(request.Type())
		}
	default:
		entry.Cost = entry.Requests * weight(template.Type())
	}
	return entry
}

func isCluster(template *templates.Template) bool {
	_, ok := template.Executer.(*templates.ClusterExecuter)
	return ok
}

// planEntryID derives the id from what the entry runs, so planning the same
// scan again yields the same ids.
func planEntryID(entry PlanEntry) string {
	sum := sha256.Sum256([]byte(entry.Target + "\x00" + entry.IP + "\x00" + strings.Join(entry.Templates, "\x00")))
	return hex.EncodeToString(sum[:8])
}
