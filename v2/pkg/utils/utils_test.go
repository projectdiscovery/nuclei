package utils

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsEmpty(t *testing.T) {
	testCases := [...][2]interface{}{
		{"", true},
		{' ', true},
		{'\t', true},
		{'\n', true},
		{" ", true},
		{"\n", true},
		{"\t", true},
		{[]string{}, true},
		{[0]string{}, true},
		{[...]string{}, true},
		{[]int{}, true},
		{[0]int{}, true},
		{[...]int{}, true},
		{interface{}(nil), true},
		{[]struct{}(nil), true},
		{[]interface{}(nil), true},
		{nil, true},

		{'a', false},
		{0, true},
		{1, false},
		{3.14, false},
		{" test ", false},
		{[]string{"a"}, false},
		{[...]string{"a"}, false},
		{[2]string{"a", "b"}, false},
		{[]int{1, 2}, false},
		{[...]int{1, 2}, false},
		{struct{ a string }{"a"}, false},
		{&struct{ a string }{"a"}, false},
		{[]struct{ a string }{{"b"}, {"b"}}, false},
	}

	for index, testCase := range testCases {
		t.Run(fmt.Sprintf("%v # %d", testCase[0], index), func(t *testing.T) {
			assert.Equal(t, testCase[1], IsEmpty(testCase[0]))
		})
	}
}
