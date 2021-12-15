package inputs

import (
	"bufio"
	"os"
)

type SimpleInputProvider struct {
	Inputs []string
}

// Count returns the number of items for input provider
func (s *SimpleInputProvider) Count() int64 {
	return int64(len(s.Inputs))
}

// Scan calls a callback function till the input provider is exhausted
func (s *SimpleInputProvider) Scan(callback func(value string)) {
	for _, v := range s.Inputs {
		callback(v)
	}
}

type FileInputProvider struct {
	Path string
}

// Count returns the number of items for input provider
func (s *FileInputProvider) Count() int64 {
	return 0
}

// Scan calls a callback function till the input provider is exhausted
func (s *FileInputProvider) Scan(callback func(value string)) {
	file, err := os.Open(s.Path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		callback(scanner.Text())
	}
}
