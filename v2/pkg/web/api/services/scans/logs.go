package scans

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ErrorLogsService stores error logs for scanID and removes them
// periodically when the files get older than 7 days.
type ErrorLogsService struct {
	directory string
	cancel    context.CancelFunc
}

// NewErrorLogsService returns a new error log service
func NewErrorLogsService(directory string) *ErrorLogsService {
	ctx, cancel := context.WithCancel(context.Background())

	service := &ErrorLogsService{
		directory: directory,
		cancel:    cancel,
	}
	go service.garbageCollect(ctx)
	return service
}

func (e *ErrorLogsService) Close() {
	e.cancel()
}

// Write returns handle to a file to write error logs to
func (e *ErrorLogsService) Write(scanid int64) (io.WriteCloser, error) {
	str := convertIDToString(scanid)
	finalPath := filepath.Join(e.directory, str)

	file, err := os.Create(finalPath)
	return file, err
}

// Read returns handle to a file to read error logs from
func (e *ErrorLogsService) Read(scanid int64) (io.ReadCloser, error) {
	str := convertIDToString(scanid)
	finalPath := filepath.Join(e.directory, str)

	file, err := os.Open(finalPath)
	return file, err
}

func convertIDToString(scanid int64) string {
	return strconv.FormatInt(scanid, 10)
}

func (e *ErrorLogsService) garbageCollect(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	for {
		select {
		case <-ticker.C:
			findAndRemoveFilesOlderThanSevenDay(e.directory)
		case <-ctx.Done():
			return
		}
	}
}

func isOlderThanSevenDays(t time.Time) bool {
	return time.Since(t) > 7*24*time.Hour
}

func findAndRemoveFilesOlderThanSevenDay(dir string) error {
	tmpfiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range tmpfiles {
		if !file.Mode().IsRegular() {
			continue
		}
		if isOlderThanSevenDays(file.ModTime()) {
			os.Remove(file.Name())
		}
	}
	return nil
}
