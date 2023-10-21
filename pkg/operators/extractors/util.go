package extractors

// SupportsMap determines if the extractor type requires a map
func SupportsMap(extractor *Extractor) bool {
	return extractor.Type.ExtractorType == KValExtractor || extractor.Type.ExtractorType == DSLExtractor
}
