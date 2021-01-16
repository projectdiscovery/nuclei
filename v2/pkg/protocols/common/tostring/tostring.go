package tostring

import "unsafe"

// UnsafeToString converts byte slice to string with zero allocations
func UnsafeToString(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}
