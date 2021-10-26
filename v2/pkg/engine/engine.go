package engine

// Engine is an engine for running Nuclei Templates/Workflows.
//
// The engine contains multiple thread pools which allow using different
// concurrency values per protocol executed. This was something which was
// missing from the previous versions of nuclei.
type Engine struct {
}
