//go:build !linux

package sandbox

func platformSupported() bool {
	return false
}

func applyPlatform(_ []string) error {
	return nil
}
