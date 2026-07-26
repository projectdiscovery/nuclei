package openapi

import (
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"
)

func TestOpenAPIExampleExclusiveBounds(t *testing.T) {
	tests := []struct {
		name   string
		schema *openapi3.Schema
		want   interface{}
	}{
		{
			name:   "OpenAPI 3.0 boolean exclusive minimum",
			schema: openapi3.NewIntegerSchema().WithMin(0).WithExclusiveMin(true),
			want:   1,
		},
		{
			name:   "OpenAPI 3.0 boolean exclusive maximum",
			schema: openapi3.NewIntegerSchema().WithMax(0).WithExclusiveMax(true),
			want:   -1,
		},
		{
			name:   "OpenAPI 3.1 numeric exclusive minimum",
			schema: openapi3.NewIntegerSchema().WithExclusiveMinValue(10),
			want:   11,
		},
		{
			name:   "OpenAPI 3.1 numeric exclusive maximum",
			schema: openapi3.NewIntegerSchema().WithExclusiveMaxValue(-10),
			want:   -11,
		},
		{
			name: "OpenAPI 3.1 numeric exclusive range",
			schema: openapi3.NewIntegerSchema().
				WithExclusiveMinValue(10).
				WithExclusiveMaxValue(12),
			want: 11,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := openAPIExample(test.schema, make(map[*openapi3.Schema]*cachedSchema))
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestOpenAPIExampleRejectsEmptyExclusiveIntegerRange(t *testing.T) {
	schema := openapi3.NewIntegerSchema().
		WithExclusiveMinValue(1).
		WithExclusiveMaxValue(2)

	_, err := openAPIExample(schema, make(map[*openapi3.Schema]*cachedSchema))
	require.True(t, errors.Is(err, ErrNoExample))
}
