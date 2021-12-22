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
	Path  string
	count int64
}

func NewFileInputProvider(filepath string) *FileInputProvider {
	fp := &FileInputProvider{Path: filepath}
	fp.count = fp.getFileLineCount(filepath)
	return fp
}

func (s *FileInputProvider) getFileLineCount(path string) int64 {
	file, err := os.Open(s.Path)
	if err != nil {
		return 0
	}
	defer file.Close()

	var count int64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count
}

// Count returns the number of items for input provider
func (s *FileInputProvider) Count() int64 {
	return s.count
}

// Scan calls a callback function till the input provider is exhausted
func (s *FileInputProvider) Scan(callback func(value string) bool) {
	file, err := os.Open(s.Path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !callback(scanner.Text()) {
			break
		}
	}
}
