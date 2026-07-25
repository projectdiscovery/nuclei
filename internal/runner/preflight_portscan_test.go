package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/require"
)

type preflightInputProviderStub struct {
	inputs []*contextargs.MetaInput
}

func (p *preflightInputProviderStub) Count() int64 {
	return int64(len(p.inputs))
}

func (p *preflightInputProviderStub) Iterate(callback func(*contextargs.MetaInput) bool) {
	for _, input := range p.inputs {
		if !callback(input) {
			return
		}
	}
}

func (*preflightInputProviderStub) Set(string, string) {}
func (*preflightInputProviderStub) SetWithProbe(string, string, inputtypes.InputLivenessProbe) error {
	return nil
}
func (*preflightInputProviderStub) SetWithExclusions(string, string) error { return nil }
func (*preflightInputProviderStub) InputType() string                      { return provider.TargetInputProvider }
func (*preflightInputProviderStub) Close()                                 {}

func TestPreflightInputKeyPreservesLegacyMarshalString(t *testing.T) {
	input := contextargs.NewMetaInput()
	input.Input = "https://example.com"
	input.CustomIP = "192.0.2.1"

	marshaled, err := input.MarshalString()
	require.NoError(t, err)

	key, err := preflightInputKey(input)
	require.NoError(t, err)
	require.Equal(t, marshaled, key)
}

func TestPreflightInputKeySeparatesPresenceAwareFilters(t *testing.T) {
	omitted := newPreflightFilteredInput(&contextargs.TargetFilter{})
	explicitEmpty := newPreflightFilteredInput(&contextargs.TargetFilter{
		HasTags: true,
		Tags:    []string{},
	})

	// TargetFilter's Has* fields are intentionally not serialized, so the old
	// MarshalString key could not distinguish these two JSONL records.
	omittedMarshaled, err := omitted.MarshalString()
	require.NoError(t, err)
	explicitEmptyMarshaled, err := explicitEmpty.MarshalString()
	require.NoError(t, err)
	require.Equal(t, omittedMarshaled, explicitEmptyMarshaled)

	omittedKey, err := preflightInputKey(omitted)
	require.NoError(t, err)
	explicitEmptyKey, err := preflightInputKey(explicitEmpty)
	require.NoError(t, err)
	require.NotEqual(t, omittedKey, explicitEmptyKey)

	// Semantically equivalent filter lists produce one stable canonical key,
	// independent of input ordering.
	firstOrdering := newPreflightFilteredInput(&contextargs.TargetFilter{
		HasTags: true,
		Tags:    []string{"beta", "alpha"},
	})
	secondOrdering := newPreflightFilteredInput(&contextargs.TargetFilter{
		HasTags: true,
		Tags:    []string{"alpha", "beta"},
	})
	firstKey, err := preflightInputKey(firstOrdering)
	require.NoError(t, err)
	secondKey, err := preflightInputKey(secondOrdering)
	require.NoError(t, err)
	require.Equal(t, firstKey, secondKey)

	allowed := mapsutil.NewSyncLockMap[string, struct{}]()
	require.NoError(t, allowed.Set(omittedKey, struct{}{}))
	require.NoError(t, allowed.Set(explicitEmptyKey, struct{}{}))

	filtered := &filteringInputProvider{
		base:     &preflightInputProviderStub{inputs: []*contextargs.MetaInput{omitted, explicitEmpty}},
		allowed:  allowed,
		allowCnt: 2,
		execID:   "test",
	}
	var iterated []*contextargs.MetaInput
	filtered.Iterate(func(input *contextargs.MetaInput) bool {
		iterated = append(iterated, input)
		return true
	})
	require.EqualValues(t, 2, filtered.Count())
	require.Len(t, iterated, 2)
}

func TestFilteringInputProviderCountsKeptInputsNotAllowedKeys(t *testing.T) {
	first := contextargs.NewMetaInput()
	first.Input = "https://duplicate.example"
	second := contextargs.NewMetaInput()
	second.Input = first.Input

	key, err := preflightInputKey(first)
	require.NoError(t, err)
	allowed := mapsutil.NewSyncLockMap[string, struct{}]()
	require.NoError(t, allowed.Set(key, struct{}{}))
	require.Len(t, allowed.GetAll(), 1)
	require.EqualValues(t, 2, countAllowedPreflightInputs([]preflightTarget{
		{key: key},
		{key: key},
	}, allowed))

	filtered := &filteringInputProvider{
		base:     &preflightInputProviderStub{inputs: []*contextargs.MetaInput{first, second}},
		allowed:  allowed,
		allowCnt: 2,
		execID:   "test",
	}
	var iterated int
	filtered.Iterate(func(*contextargs.MetaInput) bool {
		iterated++
		return true
	})

	require.EqualValues(t, 2, filtered.Count())
	require.Equal(t, 2, iterated)
}

func newPreflightFilteredInput(filter *contextargs.TargetFilter) *contextargs.MetaInput {
	input := contextargs.NewMetaInput()
	input.Input = "https://duplicate.example"
	input.TargetFilter = filter
	return input
}
