package templates

import "github.com/projectdiscovery/nuclei/v3/pkg/protocols"

// HasRequest returns true if the given requests slice is non-empty.
//
// If n is provided, it checks for more than n requests.
func HasRequest[T protocols.Request](requests []T, n ...int) bool {
	if len(n) > 0 {
		return len(requests) > n[0]
	}

	return len(requests) > 0
}

// HasDNSRequest returns true if the template has a DNS request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasDNSRequest(n ...int) bool {
	return HasRequest(t.RequestsDNS, n...)
}

// HasFileRequest returns true if the template has a File request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasFileRequest(n ...int) bool {
	return HasRequest(t.RequestsFile, n...)
}

// HasHTTPRequest returns true if the template has an HTTP request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasHTTPRequest(n ...int) bool {
	return HasRequest(t.RequestsHTTP, n...)
}

// HasHeadlessRequest returns true if the template has a Headless protocol
// request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasHeadlessRequest(n ...int) bool {
	return HasRequest(t.RequestsHeadless, n...)
}

// HasNetworkRequest returns true if the template has a Network protocol
// request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasNetworkRequest(n ...int) bool {
	return HasRequest(t.RequestsNetwork, n...)
}

// HasSSLRequest returns true if the template has an SSL request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasSSLRequest(n ...int) bool {
	return HasRequest(t.RequestsSSL, n...)
}

// HasWebsocketRequest returns true if the template has a Websocket protocol
// request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasWebsocketRequest(n ...int) bool {
	return HasRequest(t.RequestsWebsocket, n...)
}

// HasWHOISRequest returns true if the template has a WHOIS request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasWHOISRequest(n ...int) bool {
	return HasRequest(t.RequestsWHOIS, n...)
}

// HasCodeRequest returns true if the template has a Code request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasCodeRequest(n ...int) bool {
	return HasRequest(t.RequestsCode, n...)
}

// HasJavascriptRequest returns true if the template has a Javascript protocol
// request.
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasJavascriptRequest(n ...int) bool {
	return HasRequest(t.RequestsJavascript, n...)
}

// HasQueueRequests returns true if the template has queued requests.
//
// Queued requests contain all template requests in order (both protocol &
// request order).
//
// If n is provided, it checks for more than n requests.
func (t *Template) HasQueueRequests(n ...int) bool {
	return HasRequest(t.RequestsQueue, n...)
}

// HasWorkflows returns true if the template has workflows defined.
func (t *Template) HasWorkflows() bool {
	return len(t.Workflows) > 0
}

// IsFuzzableRequest returns true if the template has at least one request with
// fuzzing configured.
//
// Currently, it checks across HTTP and Headless requests.
func (t *Template) IsFuzzableRequest() bool {
	if t.HasHTTPRequest() {
		for _, request := range t.RequestsHTTP {
			if request.HasFuzzing() {
				return true
			}
		}
	}

	if t.HasHeadlessRequest() {
		for _, request := range t.RequestsHeadless {
			if request.HasFuzzing() {
				return true
			}
		}
	}

	return false
}

// IsFlowTemplate returns true if the template has a flow defined.
func (template *Template) IsFlowTemplate() bool {
	return template.Flow != "" && len(template.Flow) > 0
}

// IsGlobalMatchersTemplate returns true if the template has global matchers
// defined.
func (template *Template) IsGlobalMatchersTemplate() bool {
	return template.Options != nil &&
		template.Options.GlobalMatchers != nil &&
		template.Options.GlobalMatchers.HasMatchers()
}
