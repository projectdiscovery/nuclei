package flow

import (
	"fmt"

	"github.com/spf13/cast"
)

func declaredRequestBodySize(metadata map[string]interface{}) (int64, bool, error) {
	value, exists := metadata["max-request-body-bytes"]
	if !exists {
		return 0, false, nil
	}
	size, err := cast.ToInt64E(value)
	if err != nil || size < 0 {
		return 0, true, fmt.Errorf("invalid max-request-body-bytes metadata: %v", value)
	}
	return size, true, nil
}
