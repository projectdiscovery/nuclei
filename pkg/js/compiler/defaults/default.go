package defaults

var (
	Timeout   = 10
	Total     = 100 // == Concurrency
	NotPooled = 20
	Pooled    = Total - NotPooled
)
