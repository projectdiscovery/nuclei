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
