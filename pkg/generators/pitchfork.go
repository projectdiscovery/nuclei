package generators

// PitchforkGenerator Attack - Generate positional combinations from an input map with all values listed
// as slices of the same size
func PitchforkGenerator(payloads map[string][]string) (out chan map[string]interface{}) {
	out = make(chan map[string]interface{})

	size := 0

	// check if all wordlists have the same size
	for _, wordlist := range payloads {
		if size == 0 {
			size = len(wordlist)
		}

		if len(wordlist) != size {
			//set size = 0 and exit the cycle
			size = 0
			break
		}
	}

	// generator
	go func() {
		defer close(out)

		for i := 0; i < size; i++ {
			element := make(map[string]interface{})
			for name, wordlist := range payloads {
				element[name] = wordlist[i]
			}

			out <- element
		}
	}()

	return out
}
