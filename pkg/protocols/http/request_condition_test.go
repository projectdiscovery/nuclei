package http

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	operatorpkg "github.com/projectdiscovery/nuclei/v3/pkg/operators"
	extractorpkg "github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	matcherpkg "github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

func TestNeedsRequestConditionDurationReferences(t *testing.T) {
	tests := []struct {
		name    string
		request *Request
		want    bool
	}{
		{
			name: "duration indexed matcher dsl",
			request: &Request{
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
					DSL:  []string{"duration_1 < 1"},
				}),
			},
			want: true,
		},
		{
			name: "duration indexed matcher part",
			request: &Request{
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.WordsMatcher},
					Part: "duration_2",
				}),
			},
			want: true,
		},
		{
			name: "duration indexed extractor dsl",
			request: &Request{
				Operators: operatorsWithExtractors(&extractorpkg.Extractor{
					Type: extractorpkg.ExtractorTypeHolder{ExtractorType: extractorpkg.DSLExtractor},
					DSL:  []string{"duration_1"},
				}),
			},
			want: true,
		},
		{
			name: "deprecated req condition alone",
			request: &Request{
				ReqCondition: true,
			},
			want: false,
		},
		{
			name: "unsuffixed duration",
			request: &Request{
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
					DSL:  []string{"duration < 1"},
				}),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.request.NeedsRequestCondition())
		})
	}
}

func TestHTTPDurationRequestIDPrefixUsesID(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID:   "probe",
		Name: "display-name",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-http-prefix",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.IsMultiProtocol = true

	input := contextargs.NewWithInput(context.Background(), "http://example.com")
	executerOpts.AddTemplateVars(input.MetaInput, request.Type(), request.GetID(), output.InternalEvent{
		"duration":   float64(1),
		"duration_1": float64(0.5),
	})

	values := executerOpts.GetTemplateCtx(input.MetaInput).GetAll()
	require.Equal(t, float64(1), values["probe_duration"])
	require.Equal(t, float64(0.5), values["probe_duration_1"])
	require.NotContains(t, values, "display-name_duration")
}

func operatorsWithMatchers(matchers ...*matcherpkg.Matcher) operatorpkg.Operators {
	return operatorpkg.Operators{Matchers: matchers}
}

func operatorsWithExtractors(extractors ...*extractorpkg.Extractor) operatorpkg.Operators {
	return operatorpkg.Operators{Extractors: extractors}
}
