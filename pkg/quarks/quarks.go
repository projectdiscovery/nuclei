package quarks

// Quark is an interface implemented by each module of the scan.
//
// Each quark is an independent unit of the process connected in turn
// with multiple nodes of the entire scan process.
type Quark interface {
	// Compile returns a compiled version of the quark. Each quark requires
	// some pre-processing to be done to be able to perform execution in a
	// performant way.
	Compile() (CompiledQuark, error)
}

// CompiledQuark is the compiled version of a quark.
//
// CompiledQuark represents a very compact and generic representation
// of a quark that can be executed independently.
type CompiledQuark interface {
}

// QuarkType is the type of the input quark
type QuarkType int

// Types of quarks available for execution
const (
	TemplateQuark QuarkType = iota
	WorkflowQuark
	HTTPRequestQuark
	DNSRequestQuark
	MatcherQuark
	ExtractorQuark
)
