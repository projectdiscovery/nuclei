package generators

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeMapsMany(t *testing.T) {
	got := MergeMapsMany(map[string]interface{}{"a": []string{"1", "2"}, "c": "5"}, map[string][]string{"b": {"3", "4"}})
	require.Equal(t, map[string][]string{
		"a": {"1", "2"},
		"b": {"3", "4"},
		"c": {"5"},
	}, got, "could not get correct merged map")
}

func TestMergeMapsAndExpand(t *testing.T) {
	m1 := map[string]interface{}{"a": "1"}
	m2 := map[string]interface{}{"b": "2"}
	out := MergeMaps(m1, m2)
	if out["a"].(string) != "1" || out["b"].(string) != "2" {
		t.Fatalf("unexpected merge: %#v", out)
	}
	flat := map[string]string{"x": "y"}
	exp := ExpandMapValues(flat)
	if len(exp["x"]) != 1 || exp["x"][0] != "y" {
		t.Fatalf("unexpected expand: %#v", exp)
	}
}

func TestIteratorRemaining(t *testing.T) {
	g, err := New(map[string]interface{}{"k": []interface{}{"a", "b"}}, BatteringRamAttack, "", nil, "", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	it := g.NewIterator()
	if it.Total() != 2 || it.Remaining() != 2 {
		t.Fatalf("unexpected totals: %d %d", it.Total(), it.Remaining())
	}
	_, _ = it.Value()
	if it.Remaining() != 1 {
		t.Fatalf("unexpected remaining after one: %d", it.Remaining())
	}
}
