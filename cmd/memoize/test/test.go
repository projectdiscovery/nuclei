package memo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/bluele/gcache"
	"github.com/projectdiscovery/nuclei/v3/cmd/memoize/gotest"
)

type resStructTest struct {
	ret0Test string
}

var ()

func Test(a string, b string) string {
	var retresStructTest *resStructTest
	h := hash("Test", a, b)
	if v, err := cache.GetIFPresent(h); err == nil {
		retresStructTest = v.(*resStructTest)
	}
	retresStructTest.ret0Test = gotest.Test(a, b)
	cache.Set(h, retresStructTest)
	return retresStructTest.ret0Test
}

var (
	onceTestNothing sync.Once
)

func TestNothing() {
	onceTestNothing.Do(func() {
		gotest.TestNothing()
	})
}

var (
	onceTestWithOneReturn sync.Once
	ret0TestWithOneReturn string
)

func TestWithOneReturn() string {
	onceTestWithOneReturn.Do(func() {
		ret0TestWithOneReturn = gotest.TestWithOneReturn()
	})
	return ret0TestWithOneReturn
}

var (
	onceTestWithMultipleReturnValues sync.Once
	ret0TestWithMultipleReturnValues string

	ret1TestWithMultipleReturnValues int

	ret2TestWithMultipleReturnValues error
)

func TestWithMultipleReturnValues() (string, int, error) {
	onceTestWithMultipleReturnValues.Do(func() {
		ret0TestWithMultipleReturnValues, ret1TestWithMultipleReturnValues, ret2TestWithMultipleReturnValues = gotest.TestWithMultipleReturnValues()
	})
	return ret0TestWithMultipleReturnValues, ret1TestWithMultipleReturnValues, ret2TestWithMultipleReturnValues
}

func hash(functionName string, args ...any) string {
	var b bytes.Buffer
	b.WriteString(functionName + ":")
	for _, arg := range args {
		b.WriteString(fmt.Sprint(arg))
	}
	h := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(h[:])
}

var cache gcache.Cache[string, interface{}]

func init() {
	cache = gcache.New[string, interface{}](1000).Build()
}
