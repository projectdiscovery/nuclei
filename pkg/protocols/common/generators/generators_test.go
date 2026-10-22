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
