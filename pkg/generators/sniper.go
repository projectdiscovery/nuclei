package generators

// SniperGenerator Attack - Generate sequential combinations
func SniperGenerator(payloads map[string][]string) (out chan map[string]interface{}) {
	out = make(chan map[string]interface{})

	// generator
	go func() {
		defer close(out)

		for name, wordlist := range payloads {
			for _, value := range wordlist {
				element := CopyMapWithDefaultValue(payloads, "")
				element[name] = value
				out <- element
			}
		}
	}()

	return out
}
