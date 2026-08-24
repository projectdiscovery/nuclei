package httpclientpool

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// ErrDesyncedResponse marks a detected response that belonged to an earlier
// request and could not be safely recovered.
var ErrDesyncedResponse = errors.New("response arrived before a network round trip")

// DoWithDesyncRecovery executes req and retries it once on a fresh HTTP/1.x
// connection if net/http delivers an implausibly early response on a reused
// connection. The returned client is the one that executed the
// final attempt, and the boolean reports whether desynchronization was detected.
func DoWithDesyncRecovery(
	client *retryablehttp.Client,
	req *retryablehttp.Request,
	options *types.Options,
	configuration *Configuration,
	host string,
) (*http.Response, *retryablehttp.Client, bool, error) {
	hosts := desyncHostsFor(options)
	hostKey := desyncedHostKey(host)

	return doWithDesyncRecovery(client, req, hostKey, hosts, func(detectedHost string) (*retryablehttp.Client, error) {
		return Get(options, configuration, detectedHost)
	})
}

type desyncClientFactory func(host string) (*retryablehttp.Client, error)

func doWithDesyncRecovery(
	client *retryablehttp.Client,
	req *retryablehttp.Request,
	hostKey string,
	hosts *protocolstate.ExpiringSet,
	reissue desyncClientFactory,
) (*http.Response, *retryablehttp.Client, bool, error) {
	if client == nil || req == nil || req.Request == nil {
		return nil, client, false, fmt.Errorf("invalid HTTP client or request")
	}

	resp, err := client.Do(req)
	var desyncErr *DesyncError
	if !errors.As(err, &desyncErr) {
		return resp, client, false, err
	}

	if hosts == nil {
		return nil, client, true, fmt.Errorf("%w: %w", ErrDesyncedResponse, err)
	}
	detectedHost := hostKey
	if responseHost := desyncedHostKey(desyncErr.Host); responseHost != "" {
		detectedHost = responseHost
	}
	hosts.Store(detectedHost, desyncedHostTTL)
	countDesyncedResponse()

	if !requestReplaySafe(req.Request) {
		return nil, client, true, fmt.Errorf(
			"%w: refusing to replay non-idempotent %s request",
			ErrDesyncedResponse, req.Method,
		)
	}
	if err := rewindRequestBody(req); err != nil {
		return nil, client, true, fmt.Errorf("%w: %w", ErrDesyncedResponse, err)
	}
	reissued, err := reissue(detectedHost)
	if err != nil {
		return nil, client, true, fmt.Errorf("%w: could not create no-reuse client after HTTP desync: %w", ErrDesyncedResponse, err)
	}
	if reissued == nil {
		return nil, client, true, fmt.Errorf("%w: no-reuse client is nil after HTTP desync", ErrDesyncedResponse)
	}

	resp, err = reissued.Do(req)
	return resp, reissued, true, err
}

func requestReplaySafe(req *http.Request) bool {
	if req == nil {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	default:
		return req.Header.Get("Idempotency-Key") != ""
	}
}

func rewindRequestBody(req *retryablehttp.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return fmt.Errorf("cannot retry request after HTTP desync: request body is not replayable")
	}
	body, err := req.GetBody()
	if err != nil {
		return fmt.Errorf("cannot rewind request after HTTP desync: %w", err)
	}
	req.Body = body
	return nil
}
