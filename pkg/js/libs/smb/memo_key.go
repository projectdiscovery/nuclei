package smb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// smbMemoKey builds an unambiguous memoizer key from structured fields.
// Fields are JSON-encoded (so values containing ":" cannot collide) and hashed
// so credentials are not retained as plaintext in the memoizer key space.
func smbMemoKey(operation string, fields ...string) string {
	payload, err := json.Marshal(append([]string{operation}, fields...))
	if err != nil {
		// Extremely unlikely for []string; fall back to a distinct failure key.
		sum := sha256.Sum256([]byte(operation))
		return operation + ":err:" + hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(payload)
	return operation + ":" + hex.EncodeToString(sum[:])
}
