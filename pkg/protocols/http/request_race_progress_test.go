package http_test

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

// raceProgressCase is a race block, and what its progress ends at.
type raceProgressCase struct {
	name    string
	request *httpprotocol.Request
	// input is the target, or the test server's URL when empty.
	input string
	// down marks the target's address unresponsive.
	down bool
	// total is the number of requests the block has.
	total int64
	// errors is how many requests count as errors.
	errors int64
	// wantErr is whether the execution returns an error.
	wantErr bool
}

// raceProgressCases lists the ways a race block ends, with the copies of its
// first request it sends or leaves unsent.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func raceProgressCases(refused string) []raceProgressCase {
	const (
		copies        = 5
		refusedCopies = 1
	)

	race := func(id string, paths ...string) *httpprotocol.Request {
		return &httpprotocol.Request{ID: id, Method: methodGet(), Path: paths, Race: true, RaceNumberRequests: copies}
	}

	firstMatch := stopAtFirstMatch("race-first-match", skipPathN)
	firstMatch.Race, firstMatch.RaceNumberRequests = true, copies

	refusedRace := race("race-refused", skipPathN)
	refusedRace.RaceNumberRequests = refusedCopies

	withPayloads := race("race-payloads", skipPathPayload)
	withPayloads.Payloads = map[string]any{"v": []string{"1", "2", "3"}}

	return []raceProgressCase{
		{name: "sent", request: race("race-sent", skipPathN), total: copies},
		{
			// Copies to a refused port dial at once, and two of them are enough for a
			// data race in fastdialer's DialWrap (dialwrap.go:138, :150 and :205) in
			// some runs, so the case sends one. The count of several copies is
			// covered by errors-race in TestFailedRequestCountsOneError.
			name:    "refused",
			request: refusedRace,
			input:   "http://" + refused,
			total:   refusedCopies, errors: refusedCopies, wantErr: true,
		},
		{
			name:    "not built",
			request: race("race-not-built", "{{BaseURL}}/n?x={{to_number(\"x\")}}"),
			total:   copies, wantErr: true,
		},
		{name: "unresponsive", request: race("race-unresponsive", skipPathN), down: true, total: copies, wantErr: true},
		{name: "first match", request: firstMatch, total: copies},
		{name: "payloads", request: withPayloads, total: copies},
		{name: "several paths", request: race("race-paths", skipPathA, skipPathB), total: copies},
	}
}

// A race block sends race_count copies of its first request, so its total is
// race_count, and the copies it leaves unsent count as processed (#7838) for
// the count to end at the total (#8257).
//
//nolint:paralleltest // testutils.Init state is shared
func TestRaceProcessedRequestsEndAtTotal(t *testing.T) {
	refused := closedAddress(t)

	for _, test := range raceProgressCases(refused) {
		t.Run(test.name, func(t *testing.T) {
			server, _ := serverMissingPath(t)

			input := test.input
			if input == "" {
				input = server.URL
			}

			cache := newDownHostErrorsCache(false)
			if test.down {
				cache = newDownHostErrorsCache(false, strings.TrimPrefix(input, "http://"))
			}

			progress := compileWithCache(t, test.request, cache)

			assert.EqualValues(t, test.total, test.request.Requests(), "total")

			_, err := executeSkippable(test.request, input)

			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, test.total, progress.requests.Load(), "requests processed")
			require.Equal(t, test.errors, progress.errors.Load(), "requests counted as errors")
		})
	}
}

// A race block without race_count runs as a block that is not a race, so its
// total is its requests'.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestRaceWithoutCountKeepsRequestTotal(t *testing.T) {
	server, _ := serverMissingPath(t)
	request := &httpprotocol.Request{
		ID: "race-no-count", Method: methodGet(), Path: []string{skipPathA, skipPathB}, Race: true,
	}
	progress := compileWithCache(t, request, newDownHostErrorsCache(false))

	require.Equal(t, 2, request.Requests())

	_, err := executeSkippable(request, server.URL)

	require.NoError(t, err)
	require.EqualValues(t, 2, progress.requests.Load(), "requests processed")
}

// A race block takes the race path, which sends race_count copies, before it
// looks at fuzzing rules, so its total is race_count whatever its rules.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; testutils.Init state is shared
func TestRaceTotalComesBeforeFuzzing(t *testing.T) {
	request := &httpprotocol.Request{
		ID: "race-fuzzing", Method: methodGet(), Path: []string{skipPathN}, Race: true, RaceNumberRequests: 5,
		Fuzzing: []*fuzz.Rule{{
			Part: "query", Type: "postfix", Mode: "single", Fuzz: fuzz.SliceOrMapSlice{Value: []string{"x1", "x2"}},
		}},
	}
	compileWithCache(t, request, newDownHostErrorsCache(false))

	require.Equal(t, 5, request.Requests())
}
