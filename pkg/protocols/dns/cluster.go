package dns

// CanCluster returns true if the request can be clustered.
//
// This used by the clustering engine to decide whether two requests
// are similar enough to be considered one and can be checked by
// just adding the matcher/extractors for the request and the correct IDs.
func (request *Request) CanCluster(other *Request) bool {
	if len(request.Resolvers) > 0 || request.Trace || request.ID != "" {
		return false
	}
	if request.Name != other.Name ||
		request.class != other.class ||
		request.Retries != other.Retries ||
		request.question != other.question {
		return false
	}
	if request.Recursion != nil {
		if other.Recursion == nil {
			return false
		}
		if *request.Recursion != *other.Recursion {
			return false
		}
	}
	return true
}
