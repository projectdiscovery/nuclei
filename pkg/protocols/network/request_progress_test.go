package network //nolint:testpackage // it uses the unexported request helpers of this package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
)

const payloadName = "value"

// wordMatcher returns operators that match a response containing word, in the
// raw part so that the data an input reads counts too.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func wordMatcher(word string) operators.Operators {
	return operators.Operators{Matchers: []*matchers.Matcher{{
		Part:  "raw",
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Words: []string{word},
	}}}
}

// serverPorts returns a port for each flag: one that answers when it is true,
// and a closed one when it is false.
func serverPorts(t *testing.T, open []bool) []string {
	t.Helper()

	ports := make([]string, len(open))

	for index, answers := range open {
		address := closedAddress(t)
		if answers {
			address, _ = listen(t, nil, "ok")
		}

		_, port, err := net.SplitHostPort(address)
		require.NoError(t, err)

		ports[index] = port
	}

	return ports
}

// A listed port that the request does not send to counts as processed, with no
// error: one the port check finds closed, and one the loop does not reach after
// a stop at the first match (#8246).
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestUnstartedPortsCountAsProcessed(t *testing.T) {
	tests := []struct {
		name string
		// open says for each of the template's ports whether it answers.
		open             []bool
		payloads         int
		stopAtFirstMatch bool
		wantRequests     int64
		wantEvents       int
		wantErr          bool
	}{
		{name: "open and closed", open: []bool{true, false}, wantRequests: 2, wantEvents: 1},
		{name: "open and closed with 3 payloads", open: []bool{true, false}, payloads: 3, wantRequests: 6, wantEvents: 3},
		{name: "closed and closed", open: []bool{false, false}, wantRequests: 2, wantErr: true},
		{
			name: "open and open, stop at first match", open: []bool{true, true},
			stopAtFirstMatch: true, wantRequests: 2, wantEvents: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ports := serverPorts(t, test.open)
			request := &Request{
				Address:          []string{addressTemplate},
				Port:             strings.Join(ports, ","),
				Inputs:           []*Input{{Data: pingData}},
				Threads:          1,
				StopAtFirstMatch: test.stopAtFirstMatch,
			}

			if test.payloads > 0 {
				request.Payloads = map[string]any{payloadName: payloadValues(test.payloads)}
			}

			if test.stopAtFirstMatch {
				request.Operators = wordMatcher(okReply)
			}

			compileWithCache(t, request)
			progress := countRequests(request)

			events, err := executeCounting(request, "127.0.0.1")

			if test.wantErr {
				require.Error(t, err)
				require.NotErrorIs(t, err, hosterrorscache.ErrUnresponsiveHost)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.wantEvents, events)
			require.Equal(t, test.wantRequests, progress.requests.Load())
			require.Zero(t, progress.errors.Load())
		})
	}
}
