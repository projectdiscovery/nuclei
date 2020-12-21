package generators

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSniperGenerator(t *testing.T) {
	generator, err := New(map[string]interface{}{"username": []string{"admin", "password", "login", "test"}}, Sniper)
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	for iterator.Next() {
		fmt.Printf("value: %v\n", iterator.Value())
	}
}
