package index

import (
	"fmt"
	"testing"
)

const templateCount = 10_000

func makeMetadataCorpus(n int) []*Metadata {
	corpus := make([]*Metadata, n)
	for i := range n {
		corpus[i] = &Metadata{
			ID:           fmt.Sprintf("cve-2021-%04d", i),
			Tags:         []string{"cve", "http"},
			Authors:      []string{"tester"},
			Severity:     "critical",
			ProtocolType: "http",
		}
	}
	return corpus
}

// mixedFilter builds a realistic filter: exactIDs exact IDs (~1/3 match corpus) + wildcardPatterns glob patterns (no match)
func mixedFilter(exactIDs, wildcardPatterns int) *Filter {
	ids := make([]string, 0, exactIDs+wildcardPatterns)
	for i := range exactIDs {
		ids = append(ids, fmt.Sprintf("cve-202%d-%04d", i%3, i)) // ~1/3 hit corpus (year 2021)
	}
	for i := range wildcardPatterns {
		ids = append(ids, fmt.Sprintf("sqli-%04d-*", i)) // wildcard, no match
	}
	return &Filter{IDs: ids}
}

func BenchmarkFilterMatches(b *testing.B) {
	corpus := makeMetadataCorpus(templateCount)

	cases := []struct{ exact, wildcards int }{
		{10, 0},
		{100, 0},
		{1000, 0},
		{100, 1},
		{100, 3},
		{100, 5},
	}

	for _, tc := range cases {
		b.Run(fmt.Sprintf("ids=%d,patterns=%d", tc.exact, tc.wildcards), func(b *testing.B) {
			b.ReportAllocs()

			filter := mixedFilter(tc.exact, tc.wildcards)
			filter.Compile()
			for b.Loop() {
				for _, meta := range corpus {
					_ = filter.matchesIncludeID(meta.ID)
				}
			}
		})
	}
}
