//go:build !stats
// +build !stats

package events

// AddScanEvent is a no-op function
func AddScanEvent(event ScanEvent) {
}

func InitWithConfig(config *ScanConfig, statsDirectory string) {
}

func Close() {
}
