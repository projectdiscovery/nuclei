package common

import (
	"math/rand"
	"time"
)

var mathrand *rand.Rand

func init() {
	mathrand = rand.New(rand.NewSource(time.Now().UnixNano()))
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

// RandString generates a random string of n length
func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[mathrand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
