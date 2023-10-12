package common

import (
	"fmt"
	"testing"
)

func TestRandASCIIBytes(t *testing.T) {
	data := RandString(6)
	if len(data) != 6 {
		t.Fatal("invalid data")
	}
	fmt.Println(data)
}
