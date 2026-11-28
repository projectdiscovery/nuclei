package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// Numbered response parts (status_code_1, status_code_2, ...) must keep working
// when the raw requests of the block use payload values:
//   - with threads (or -payload-concurrency) the block used to run on the
//     parallel path, which numbers every request 0;
//   - on the sequential path the parts of the previous payload combination
//     stayed in the history, so request 1 of the next combination matched on
//     the previous combination's status_code_2.
//
//nolint:paralleltest // testutils.Init state is shared
func TestRequestConditionWithPayloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok && user == "admin" && pass == "admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	for _, threads := range []int{0, 10} {
		t.Run("threads "+map[int]string{0: "unset", 10: "10"}[threads], func(t *testing.T) {
			//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
			request := &httpprotocol.Request{
				ID: "req-condition-payloads",
				Raw: []string{
					"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\nAuthorization: Basic aW52YWxpZA==\r\n\r\n",
					"GET / HTTP/1.1\r\nHost: {{Hostname}}\r\nAuthorization: Basic {{base64(username + ':' + password)}}\r\n\r\n",
				},
				AttackType: generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
				Payloads: map[string]any{
					"username": []string{"admin", "test"},
					"password": []string{"test", "admin"},
				},
				Threads: threads,
				Operators: operators.Operators{
					Matchers: []*matchers.Matcher{{
						Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
						DSL:  []string{"status_code_1 == 401 && status_code_2 == 200"},
					}},
				},
			}
			compileWithCache(t, request, newDownHostErrorsCache(false))

			require.Zero(t, request.Threads, "numbered request conditions need the sequential path")

			var matched atomic.Int32

			err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), server.URL),
				make(output.InternalEvent), make(output.InternalEvent),
				func(event *output.InternalWrappedEvent) {
					if event.OperatorsResult != nil && event.OperatorsResult.Matched {
						matched.Add(1)
					}
				})
			require.NoError(t, err)
			require.Equal(t, int32(1), matched.Load(), "only the admin:admin combination matches")
		})
	}
}

// runRequestCondition compiles and runs a two-request block with a pitchfork
// over the given credentials and returns how many events matched.
func runRequestCondition(t *testing.T, serverURL string, dsl string, users, passwords []string) (int32, error) {
	t.Helper()

	//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
	request := &httpprotocol.Request{
		ID: "req-condition-history",
		Raw: []string{
			"GET /first HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
			"GET /second HTTP/1.1\r\nHost: {{Hostname}}\r\nAuthorization: Basic {{base64(username + ':' + password)}}\r\n\r\n",
		},
		AttackType: generators.AttackTypeHolder{Value: generators.PitchForkAttack},
		Payloads:   map[string]any{"username": users, "password": passwords},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
				DSL:  []string{dsl},
			}},
		},
	}
	compileWithCache(t, request, newDownHostErrorsCache(false))

	var matched atomic.Int32

	err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), serverURL),
		make(output.InternalEvent), make(output.InternalEvent),
		func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matched.Add(1)
			}
		})

	return matched.Load(), err
}

// A request that fails must not leave the previous payload combination's
// numbered parts in place: request 1 of the second combination fails, so
// status_code_1 of the first combination must not pair with its status_code_2.
//
//nolint:paralleltest // testutils.Init state is shared
func TestRequestConditionWithPayloadsFailedRequest(t *testing.T) {
	var firstHits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			if firstHits.Add(1) > 1 {
				// every later /first fails, retries included
				hijacker, ok := w.(http.Hijacker)
				require.True(t, ok)
				conn, _, err := hijacker.Hijack()
				require.NoError(t, err)
				_ = conn.Close()
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, _, ok := r.BasicAuth(); ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	matched, _ := runRequestCondition(t, server.URL, "status_code_1 == 401 && status_code_2 == 200",
		[]string{"admin", "root"}, []string{"admin", "root"})
	require.Equal(t, int32(1), matched, "only the first combination, whose request 1 succeeded, matches")
}

// Parts that only some responses carry (headers, cookies) must not survive into
// a later payload combination whose response doesn't send them.
//
//nolint:paralleltest // testutils.Init state is shared
func TestRequestConditionWithPayloadsStaleHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/second" {
			if user, _, ok := r.BasicAuth(); ok && user == "admin" {
				w.Header().Set("X-Authenticated", "yes")
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	matched, err := runRequestCondition(t, server.URL, "status_code_1 == 200 && x_authenticated_2 == 'yes'",
		[]string{"admin", "guest"}, []string{"admin", "guest"})
	require.NoError(t, err)
	require.Equal(t, int32(1), matched, "only the admin combination sends X-Authenticated")
}
