package generators

// Sniper performs sequential combination of provided items
func Sniper(payloads map[string][]string) chan map[string]interface{} {
	out := make(chan map[string]interface{})

	go func(out chan map[string]interface{}) {
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
