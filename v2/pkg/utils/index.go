package utils

// TransformIndex transforms user given index (start from 1) to array index (start from 0)
// in safe way without panic i.e negative index or index out of range
func TransformIndex[T any](arr []T, index int) int {
	if index <= 1 {
		// negative index
		return 0
	}
	if index >= len(arr) {
		// index out of range
		return len(arr) - 1
	}
	// valid index
	return index - 1
}
