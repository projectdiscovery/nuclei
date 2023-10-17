package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <templates-directory> <checksum-file>\n", os.Args[0])
	}
	checksumFile := os.Args[2]
	templatesDirectory := os.Args[1]

	file, err := os.Create(checksumFile)
	if err != nil {
		log.Fatalf("Could not create file: %s\n", err)
	}
	defer file.Close()

	err = filepath.WalkDir(templatesDirectory, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		pathIndex := path[strings.Index(path, "nuclei-templates/")+17:]
		pathIndex = strings.TrimPrefix(pathIndex, "nuclei-templates/")
		// Ignore items starting with dots
		if strings.HasPrefix(pathIndex, ".") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		h := sha1.New()
		_, _ = io.Copy(h, bytes.NewReader(data))
		hash := hex.EncodeToString(h.Sum(nil))

		_, _ = file.WriteString(pathIndex)
		_, _ = file.WriteString(":")
		_, _ = file.WriteString(hash)
		_, _ = file.WriteString("\n")
		return nil
	})
	if err != nil {
		log.Fatalf("Could not walk directory: %s\n", err)
	}
}
