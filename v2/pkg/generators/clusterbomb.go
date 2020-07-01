package generators

// ClusterbombGenerator Attack - Generate all possible combinations from an input map with all values listed
// as slices of the same size
func ClusterbombGenerator(payloads map[string][]string) (out chan map[string]interface{}) {
	out = make(chan map[string]interface{})

	// generator
	go func() {
		defer close(out)
		var order []string
		var parts [][]string
		for name, wordlist := range payloads {
			order = append(order, name)
			parts = append(parts, wordlist)
		}

		var n = 1
		for _, ar := range parts {
			n *= len(ar)
		}

		var at = make([]int, len(parts))
	loop:
		for {
			// increment position counters
			for i := len(parts) - 1; i >= 0; i-- {
				if at[i] > 0 && at[i] >= len(parts[i]) {
					if i == 0 || (i == 1 && at[i-1] == len(parts[0])-1) {
						break loop
					}
					at[i] = 0
					at[i-1]++
				}
			}
			// construct permutation
			item := make(map[string]interface{})
			for i, ar := range parts {
				var p = at[i]
				if p >= 0 && p < len(ar) {
					item[order[i]] = ar[p]
				}
			}
			out <- item
			at[len(parts)-1]++
		}
	}()

	return out
}
