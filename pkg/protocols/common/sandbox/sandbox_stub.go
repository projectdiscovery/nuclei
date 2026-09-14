//go:build !linux

package sandbox

func platformSupported() bool {
	return false
}

func applyPlatform(_ []string, _ bool) error {
	return nil
}
