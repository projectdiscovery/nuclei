package fuzz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValueOrKeyValue_IsKV(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected bool
	}{
		{"with key", "key", "value", true},
		{"without key", "", "value", false},
		{"empty both", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &ValueOrKeyValue{
				Key:   tt.key,
				Value: tt.value,
			}
			require.Equal(t, tt.expected, v.IsKV())
		})
	}
}

func TestValueOrKeyValue_Validate(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid", "value", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &ValueOrKeyValue{
				Key:   "key",
				Value: tt.value,
			}
			err := v.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValueOrKeyValue_String(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		expected string
	}{
		{"with key", "key", "value", "key=value"},
		{"without key", "", "value", "value"},
		{"empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &ValueOrKeyValue{
				Key:   tt.key,
				Value: tt.value,
			}
			require.Equal(t, tt.expected, v.String())
		})
	}
}

func TestSliceOrMapSlice_Len(t *testing.T) {
	tests := []struct {
		name     string
		value    []string
		kv       map[string]string
		expected int
	}{
		{"value mode", []string{"a", "b", "c"}, nil, 3},
		{"kv mode", nil, map[string]string{"a": "1", "b": "2"}, 2},
		{"empty value", []string{}, nil, 0},
		{"empty kv", nil, map[string]string{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := SliceOrMapSlice{
				Value: tt.value,
			}
			if tt.kv != nil {
				v.KV = nil // Will be initialized by Set
				for k, val := range tt.kv {
					v.Set(k, val)
				}
			}
			require.Equal(t, tt.expected, v.Len())
		})
	}
}

func TestSliceOrMapSlice_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		value    []string
		expected bool
	}{
		{"not empty", []string{"a"}, false},
		{"empty", []string{}, true},
		{"nil", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := SliceOrMapSlice{
				Value: tt.value,
			}
			require.Equal(t, tt.expected, v.IsEmpty())
		})
	}
}

func TestSliceOrMapSlice_Validate(t *testing.T) {
	tests := []struct {
		name    string
		value   []string
		wantErr bool
	}{
		{"valid value", []string{"a"}, false},
		{"valid kv", nil, false},
		{"empty value", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := SliceOrMapSlice{
				Value: tt.value,
			}
			err := v.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSliceOrMapSlice_GetSet(t *testing.T) {
	v := SliceOrMapSlice{}
	
	// Test Set
	v.Set("key1", "value1")
	v.Set("key2", "value2")
	
	// Test Get
	val, ok := v.Get("key1")
	require.True(t, ok)
	require.Equal(t, "value1", val)
	
	val, ok = v.Get("key2")
	require.True(t, ok)
	require.Equal(t, "value2", val)
	
	// Test Get non-existent
	_, ok = v.Get("key3")
	require.False(t, ok)
}

func TestSliceOrMapSlice_Append(t *testing.T) {
	v := SliceOrMapSlice{}
	
	v.Append("a")
	v.Append("b")
	v.Append("c")
	
	require.Equal(t, 3, v.Len())
	require.Equal(t, []string{"a", "b", "c"}, v.Value)
}
