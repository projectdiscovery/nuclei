package generators

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/stretchr/testify/require"
)

func TestBatteringRamGenerator(t *testing.T) {
	usernames := []string{"admin", "password"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames}, BatteringRamAttack, "", catalogInstance, "", getOptions(false))
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	count := 0
	for {
		_, ok := iterator.Value()
		if !ok {
			break
		}
		count++
	}
	require.Equal(t, len(usernames), count, "could not get correct batteringram counts")
}

func TestPitchforkGenerator(t *testing.T) {
	usernames := []string{"admin", "token"}
	passwords := []string{"password1", "password2", "password3"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames, "password": passwords}, PitchForkAttack, "", catalogInstance, "", getOptions(false))
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	count := 0
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		count++
		require.Contains(t, usernames, value["username"], "Could not get correct pitchfork username")
		require.Contains(t, passwords, value["password"], "Could not get correct pitchfork password")
	}
	require.Equal(t, len(usernames), count, "could not get correct pitchfork counts")
}

func TestClusterbombGenerator(t *testing.T) {
	usernames := []string{"admin"}
	passwords := []string{"admin", "password", "token"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames, "password": passwords}, ClusterBombAttack, "", catalogInstance, "", getOptions(false))
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	count := 0
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		count++
		require.Contains(t, usernames, value["username"], "Could not get correct clusterbomb username")
		require.Contains(t, passwords, value["password"], "Could not get correct clusterbomb password")
	}
	require.Equal(t, 3, count, "could not get correct clusterbomb counts")

	iterator.Reset()
	count = 0
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		count++
		require.Contains(t, usernames, value["username"], "Could not get correct clusterbomb username")
		require.Contains(t, passwords, value["password"], "Could not get correct clusterbomb password")
	}
	require.Equal(t, 3, count, "could not get correct clusterbomb counts")
}

func getOptions(allowLocalFileAccess bool) *types.Options {
	opts := types.DefaultOptions()
	opts.AllowLocalFileAccess = allowLocalFileAccess
	return opts
}

// collect drains an iterator into a slice of "key=value|key=value" strings so
// that a combination can be compared regardless of the order it is produced in.
func collect(iterator *Iterator) []string {
	var got []string
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, value[k]))
		}
		got = append(got, strings.Join(parts, "|"))
	}
	return got
}

func randomOptions() *types.Options {
	opts := getOptions(false)
	opts.PayloadRandomOrder = true
	return opts
}

func TestBatteringRamRandomOrder(t *testing.T) {
	usernames := []string{"admin", "root", "guest", "operator", "test"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames}, BatteringRamAttack, "", catalogInstance, "", randomOptions())
	require.Nil(t, err, "could not create generator")

	want := []string{"username=admin", "username=root", "username=guest", "username=operator", "username=test"}

	// every iterator must cover all combinations, and across several iterators
	// the order must not always be the same one.
	orders := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		got := collect(generator.NewIterator())
		require.ElementsMatch(t, want, got, "random order must visit every combination exactly once")
		orders[strings.Join(got, ",")] = struct{}{}
	}
	require.Greater(t, len(orders), 1, "random order should not be deterministic")
}

func TestPitchforkRandomOrder(t *testing.T) {
	usernames := []string{"admin", "root", "guest", "operator"}
	passwords := []string{"password1", "password2", "password3", "password4"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames, "password": passwords}, PitchForkAttack, "", catalogInstance, "", randomOptions())
	require.Nil(t, err, "could not create generator")

	got := collect(generator.NewIterator())

	// pitchfork keeps the same pairs as the sequential run, only the order changes
	want := []string{
		"password=password1|username=admin",
		"password=password2|username=root",
		"password=password3|username=guest",
		"password=password4|username=operator",
	}
	require.ElementsMatch(t, want, got, "random pitchfork must keep the index-aligned pairs")
}

func TestClusterbombRandomOrder(t *testing.T) {
	usernames := []string{"admin", "root", "guest"}
	passwords := []string{"password", "token", "secret"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames, "password": passwords}, ClusterBombAttack, "", catalogInstance, "", randomOptions())
	require.Nil(t, err, "could not create generator")

	random := collect(generator.NewIterator())

	sequentialGen, err := New(map[string]interface{}{"username": usernames, "password": passwords}, ClusterBombAttack, "", catalogInstance, "", getOptions(false))
	require.Nil(t, err, "could not create generator")
	sequential := collect(sequentialGen.NewIterator())

	require.Len(t, random, len(usernames)*len(passwords), "random clusterbomb must produce every combination")
	require.ElementsMatch(t, sequential, random, "random clusterbomb must cover the same combinations as the sequential one")
}

// TestRandomOrderDisabledByDefault guards that the flag is strictly opt-in: a
// generator built without it keeps the sequential path (no shuffled order).
func TestRandomOrderDisabledByDefault(t *testing.T) {
	payloads := map[string]interface{}{"username": []string{"admin", "root"}, "password": []string{"a", "b"}}
	catalogInstance := disk.NewCatalog("")

	sequentialGen, err := New(payloads, ClusterBombAttack, "", catalogInstance, "", getOptions(false))
	require.Nil(t, err, "could not create generator")
	require.Nil(t, sequentialGen.NewIterator().perm, "random order must be off unless requested")

	randomGen, err := New(payloads, ClusterBombAttack, "", catalogInstance, "", randomOptions())
	require.Nil(t, err, "could not create generator")
	require.NotNil(t, randomGen.NewIterator().perm, "random order must be on when requested")
}

// TestRandomOrderTotalsAndReset checks that the random path reports the same
// Total and Remaining as the sequential one, that Reset replays the same order,
// and that a single-combination set is handled.
func TestRandomOrderTotalsAndReset(t *testing.T) {
	catalogInstance := disk.NewCatalog("")

	generator, err := New(map[string]interface{}{"username": []string{"admin", "root", "guest"}, "password": []string{"a", "b"}}, ClusterBombAttack, "", catalogInstance, "", randomOptions())
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	require.Equal(t, 6, iterator.Total(), "Total must count every combination regardless of order")
	require.Equal(t, 6, iterator.Remaining(), "Remaining must start at the combination total")

	first := collect(iterator)
	require.Len(t, first, 6, "every combination must be produced once")
	require.Equal(t, 0, iterator.Remaining(), "no combinations may remain once drained")

	iterator.Reset()
	require.Equal(t, 6, iterator.Remaining(), "Reset must restore the full count")
	second := collect(iterator)
	require.Equal(t, first, second, "Reset must replay the same random order")

	// a single-combination set must still yield exactly that combination
	single, err := New(map[string]interface{}{"username": []string{"only"}}, BatteringRamAttack, "", catalogInstance, "", randomOptions())
	require.Nil(t, err, "could not create generator")
	require.Equal(t, []string{"username=only"}, collect(single.NewIterator()))
}

// TestRandomOrderCoversLargeAwkwardTotals exercises the on-demand permutation
// on totals that are not powers of two and larger than the tiny cases above, so
// the Feistel cycle-walking is driven hard. Every combination must still appear
// exactly once, with no index allocated up front.
func TestRandomOrderCoversLargeAwkwardTotals(t *testing.T) {
	catalogInstance := disk.NewCatalog("")

	build := func(n int, prefix string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%s%d", prefix, i)
		}
		return out
	}

	testCases := []struct {
		name     string
		payloads map[string]interface{}
		attack   AttackType
		total    int
	}{
		{"batteringram-50", map[string]interface{}{"u": build(50, "u")}, BatteringRamAttack, 50},
		{"clusterbomb-12x13", map[string]interface{}{"u": build(12, "u"), "p": build(13, "p")}, ClusterBombAttack, 156},
		{"clusterbomb-7x11x13", map[string]interface{}{"u": build(7, "u"), "p": build(11, "p"), "h": build(13, "h")}, ClusterBombAttack, 1001},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			randomGen, err := New(testCase.payloads, testCase.attack, "", catalogInstance, "", randomOptions())
			require.Nil(t, err, "could not create generator")
			random := collect(randomGen.NewIterator())

			sequentialGen, err := New(testCase.payloads, testCase.attack, "", catalogInstance, "", getOptions(false))
			require.Nil(t, err, "could not create generator")
			sequential := collect(sequentialGen.NewIterator())

			require.Len(t, random, testCase.total, "random order must produce every combination")
			require.Len(t, uniq(random), testCase.total, "random order must not repeat a combination")
			require.ElementsMatch(t, sequential, random, "random order must cover the same combinations as the sequential one")
		})
	}
}

// uniq returns the distinct values of in, preserving nothing but membership.
func uniq(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func TestParsePayloadsWithAggression(t *testing.T) {
	testPayload := `linux_path:
  low:
    - /etc/passwd
  medium:
    - ../etc/passwd
    - ../../etc/passwd
  high:
    - ../../../etc/passwd
    - ../../../../etc/passwd
    - ../../../../../etc/passwd`

	var payloads map[string]interface{}
	err := yaml.NewDecoder(strings.NewReader(testPayload)).Decode(&payloads)
	require.Nil(t, err, "could not unmarshal yaml")

	aggressionsToValues := map[string][]string{
		"low": {
			"/etc/passwd",
		},
		"medium": {
			"/etc/passwd",
			"../etc/passwd",
			"../../etc/passwd",
		},
		"high": {
			"/etc/passwd",
			"../etc/passwd",
			"../../etc/passwd",
			"../../../etc/passwd",
			"../../../../etc/passwd",
			"../../../../../etc/passwd",
		},
	}

	for k, v := range payloads {
		for aggression, values := range aggressionsToValues {
			parsed, err := parsePayloadsWithAggression(k, v.(map[interface{}]interface{}), aggression)
			require.Nil(t, err, "could not parse payloads with aggression")

			gotValues := parsed[k].([]interface{})
			require.Equal(t, len(values), len(gotValues), "could not get correct number of values")
		}
	}
}
