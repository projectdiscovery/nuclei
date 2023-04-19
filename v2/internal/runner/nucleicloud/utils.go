package nucleicloud

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
)

const DDMMYYYYhhmmss = "2006-01-02 15:04:05"

// ReadCatalogChecksum reads catalog checksum from nuclei-templates repository
func ReadCatalogChecksum() map[string]string {
	config := config.DefaultConfig

	checksumFile := filepath.Join(config.TemplatesDirectory, "templates-checksum.txt")
	file, err := os.Open(checksumFile)
	if err != nil {
		return nil
	}
	defer file.Close()

	checksums := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.SplitN(scanner.Text(), ":", 2)
		if len(text) < 2 {
			continue
		}
		path := strings.TrimPrefix(text[0], "nuclei-templates/")
		if strings.HasPrefix(path, ".") {
			continue
		}
		checksums[path] = text[1]
	}
	return checksums
}

func PrepareScanListOutput(v GetScanRequest) ListScanOutput {
	output := ListScanOutput{}
	loc, _ := time.LoadLocation("Local")
	status := "finished"

	t := v.FinishedAt
	duration := t.Sub(v.CreatedAt)

	if !v.Finished {
		status = "running"
		t = time.Now().UTC()
		duration = t.Sub(v.CreatedAt).Round(60 * time.Second)
	}

	val := v.CreatedAt.In(loc).Format(DDMMYYYYhhmmss)

	output.Timestamp = val
	output.ScanID = v.Id
	output.ScanTime = duration.String()
	output.ScanResult = int(v.Matches)
	output.ScanStatus = status
	output.Target = int(v.Targets)
	output.Template = int(v.Templates)
	return output
}
