package replay

import (
	"encoding/base64"
	"unicode/utf8"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// Matchers type-assert some values, such as an int status code or a []string
// of dns answers, and binary responses are not valid UTF-8, so plain JSON
// would change what they see. Those values are wrapped in a one-key object
// naming their Go type; everything else is stored as JSON.
const (
	tagBytes   = "$bytes"
	tagBinary  = "$binary"
	tagInt     = "$int"
	tagStrings = "$strings"
)

func encodeEvent(event output.InternalEvent) map[string]any {
	encoded := make(map[string]any, len(event))
	for key, value := range event {
		switch v := value.(type) {
		case string:
			if utf8.ValidString(v) {
				encoded[key] = v
			} else {
				encoded[key] = map[string]string{tagBinary: base64.StdEncoding.EncodeToString([]byte(v))}
			}
		case []byte:
			encoded[key] = map[string]string{tagBytes: base64.StdEncoding.EncodeToString(v)}
		case int:
			encoded[key] = map[string]int{tagInt: v}
		case []string:
			encoded[key] = map[string][]string{tagStrings: v}
		default:
			// values JSON cannot hold, such as funcs, are not something a
			// matcher reads
			if _, err := json.Marshal(v); err == nil {
				encoded[key] = v
			}
		}
	}
	return encoded
}

func decodeEvent(raw map[string]json.Message) (output.InternalEvent, error) {
	event := make(output.InternalEvent, len(raw))
	for key, message := range raw {
		value, err := decodeValue(message)
		if err != nil {
			return nil, err
		}
		event[key] = value
	}
	return event, nil
}

func decodeValue(message json.Message) (any, error) {
	var tagged map[string]json.Message
	if json.Unmarshal(message, &tagged) == nil && len(tagged) == 1 {
		for tag, inner := range tagged {
			switch tag {
			case tagBytes, tagBinary:
				var text string
				if err := json.Unmarshal(inner, &text); err != nil {
					return nil, err
				}
				data, err := base64.StdEncoding.DecodeString(text)
				if err != nil {
					return nil, err
				}
				if tag == tagBinary {
					return string(data), nil
				}
				return data, nil
			case tagInt:
				var number int
				err := json.Unmarshal(inner, &number)
				return number, err
			case tagStrings:
				var list []string
				err := json.Unmarshal(inner, &list)
				return list, err
			}
		}
	}
	var value any
	err := json.Unmarshal(message, &value)
	return value, err
}
