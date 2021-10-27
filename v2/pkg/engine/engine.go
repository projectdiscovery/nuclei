package engine

// Engine is an engine for running Nuclei Templates/Workflows.
//
// The engine contains multiple thread pools which allow using different
// concurrency values per protocol executed. This was something which was
// missing from the previous versions of nuclei.
type Engine struct {
}

// InputProvider is an input provider interface for the nuclei execution
// engine.
//
// An example InputProvider is provided in form of hmap input provider.
type InputProvider interface {
}
