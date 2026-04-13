package index

import (
	"fmt"
	"testing"
)

// templateCount simulates a realistic nuclei template corpus size.
const templateCount = 10_000

// makeMetadataCorpus returns a slice of metadata entries with sequential IDs.
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

// mixedFilter builds a realistic filter: exactIDs exact IDs (~1/3 match corpus)
// + wildcardPatterns glob patterns (no match), reflecting typical usage
// of nuclei -id flags alongside tag-style wildcards.
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

// BenchmarkFilterMatches_Mixed benchmarks a realistic mix of exact IDs and
// wildcard patterns against the full 7000-template corpus.
// Sub-benchmarks vary the number of wildcard patterns (0-5) at a fixed
// base of 100 exact IDs, matching typical production invocations.
func BenchmarkFilterMatches_Mixed(b *testing.B) {
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

// BenchmarkFilterMatches_Mixed_Old is the equivalent pre-fix scan for comparison:
// raw matchesID loop over all IDs+patterns per template.
func BenchmarkFilterMatches_Mixed_Old(b *testing.B) {
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

			ids := mixedFilter(tc.exact, tc.wildcards).IDs
			for b.Loop() {
				for _, meta := range corpus {
					matched := false
					for _, id := range ids {
						if matchesID(meta.ID, id) {
							matched = true
							break
						}
					}
					_ = matched
				}
			}
		})
	}
}
