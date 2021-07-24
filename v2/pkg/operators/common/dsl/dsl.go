package dsl

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"math"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/deserialization"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/spaolacci/murmur3"
)

const (
	numbers              = "1234567890"
	letters              = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	withCutSetArgsSize   = 2
	withBaseRandArgsSize = 3
	withMaxRandArgsSize  = withCutSetArgsSize
)

var functions = map[string]govaluate.ExpressionFunction{
	"len": func(args ...interface{}) (interface{}, error) {
		length := len(types.ToString(args[0]))
		return float64(length), nil
	},
	"toupper": func(args ...interface{}) (interface{}, error) {
		return strings.ToUpper(types.ToString(args[0])), nil
	},
	"tolower": func(args ...interface{}) (interface{}, error) {
		return strings.ToLower(types.ToString(args[0])), nil
	},
	"replace": func(args ...interface{}) (interface{}, error) {
		return strings.ReplaceAll(types.ToString(args[0]), types.ToString(args[1]), types.ToString(args[2])), nil
	},
	"replace_regex": func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(types.ToString(args[1]))
		if err != nil {
			return nil, err
		}
		return compiled.ReplaceAllString(types.ToString(args[0]), types.ToString(args[2])), nil
	},
	"trim": func(args ...interface{}) (interface{}, error) {
		return strings.Trim(types.ToString(args[0]), types.ToString(args[2])), nil
	},
	"trimleft": func(args ...interface{}) (interface{}, error) {
		return strings.TrimLeft(types.ToString(args[0]), types.ToString(args[1])), nil
	},
	"trimright": func(args ...interface{}) (interface{}, error) {
		return strings.TrimRight(types.ToString(args[0]), types.ToString(args[1])), nil
	},
	"trimspace": func(args ...interface{}) (interface{}, error) {
		return strings.TrimSpace(types.ToString(args[0])), nil
	},
	"trimprefix": func(args ...interface{}) (interface{}, error) {
		return strings.TrimPrefix(types.ToString(args[0]), types.ToString(args[1])), nil
	},
	"trimsuffix": func(args ...interface{}) (interface{}, error) {
		return strings.TrimSuffix(types.ToString(args[0]), types.ToString(args[1])), nil
	},
	"reverse": func(args ...interface{}) (interface{}, error) {
		return reverseString(types.ToString(args[0])), nil
	},
	// encoding
	"base64": func(args ...interface{}) (interface{}, error) {
		sEnc := base64.StdEncoding.EncodeToString([]byte(types.ToString(args[0])))

		return sEnc, nil
	},
	// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
	"base64_py": func(args ...interface{}) (interface{}, error) {
		sEnc := base64.StdEncoding.EncodeToString([]byte(types.ToString(args[0])))
		return deserialization.InsertInto(sEnc, 76, '\n'), nil
	},
	"base64_decode": func(args ...interface{}) (interface{}, error) {
		return base64.StdEncoding.DecodeString(types.ToString(args[0]))
	},
	"url_encode": func(args ...interface{}) (interface{}, error) {
		return url.PathEscape(types.ToString(args[0])), nil
	},
	"url_decode": func(args ...interface{}) (interface{}, error) {
		return url.PathUnescape(types.ToString(args[0]))
	},
	"hex_encode": func(args ...interface{}) (interface{}, error) {
		return hex.EncodeToString([]byte(types.ToString(args[0]))), nil
	},
	"hex_decode": func(args ...interface{}) (interface{}, error) {
		hx, _ := hex.DecodeString(types.ToString(args[0]))
		return string(hx), nil
	},
	"html_escape": func(args ...interface{}) (interface{}, error) {
		return html.EscapeString(types.ToString(args[0])), nil
	},
	"html_unescape": func(args ...interface{}) (interface{}, error) {
		return html.UnescapeString(types.ToString(args[0])), nil
	},
	// hashing
	"md5": func(args ...interface{}) (interface{}, error) {
		hash := md5.Sum([]byte(types.ToString(args[0])))

		return hex.EncodeToString(hash[:]), nil
	},
	"sha256": func(args ...interface{}) (interface{}, error) {
		h := sha256.New()
		_, err := h.Write([]byte(types.ToString(args[0])))

		if err != nil {
			return nil, err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	},
	"sha1": func(args ...interface{}) (interface{}, error) {
		h := sha1.New()
		_, err := h.Write([]byte(types.ToString(args[0])))

		if err != nil {
			return nil, err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	},
	"mmh3": func(args ...interface{}) (interface{}, error) {
		return fmt.Sprintf("%d", int32(murmur3.Sum32WithSeed([]byte(types.ToString(args[0])), 0))), nil
	},
	// search
	"contains": func(args ...interface{}) (interface{}, error) {
		return strings.Contains(types.ToString(args[0]), types.ToString(args[1])), nil
	},
	"regex": func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(types.ToString(args[0]))
		if err != nil {
			return nil, err
		}
		return compiled.MatchString(types.ToString(args[1])), nil
	},
	// random generators
	"rand_char": func(args ...interface{}) (interface{}, error) {
		chars := letters + numbers
		bad := ""
		if len(args) >= 1 {
			chars = types.ToString(args[0])
		}
		if len(args) >= withCutSetArgsSize {
			bad = types.ToString(args[1])
		}
		chars = trimAll(chars, bad)
		return chars[rand.Intn(len(chars))], nil
	},
	"rand_base": func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		base := letters + numbers

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= withCutSetArgsSize {
			bad = types.ToString(args[1])
		}
		if len(args) >= withBaseRandArgsSize {
			base = types.ToString(args[2])
		}
		base = trimAll(base, bad)
		return randSeq(base, l), nil
	},
	"rand_text_alphanumeric": func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		chars := letters + numbers

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= withCutSetArgsSize {
			bad = types.ToString(args[1])
		}
		chars = trimAll(chars, bad)
		return randSeq(chars, l), nil
	},
	"rand_text_alpha": func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		chars := letters

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= withCutSetArgsSize {
			bad = types.ToString(args[1])
		}
		chars = trimAll(chars, bad)
		return randSeq(chars, l), nil
	},
	"rand_text_numeric": func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		chars := numbers

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= withCutSetArgsSize {
			bad = types.ToString(args[1])
		}
		chars = trimAll(chars, bad)
		return randSeq(chars, l), nil
	},
	"rand_int": func(args ...interface{}) (interface{}, error) {
		min := 0
		max := math.MaxInt32

		if len(args) >= 1 {
			min = args[0].(int)
		}
		if len(args) >= withMaxRandArgsSize {
			max = args[1].(int)
		}
		return rand.Intn(max-min) + min, nil
	},
	// Time Functions
	"waitfor": func(args ...interface{}) (interface{}, error) {
		seconds := args[0].(float64)
		time.Sleep(time.Duration(seconds) * time.Second)
		return true, nil
	},
	// deserialization Functions
	"generate_java_gadget": func(args ...interface{}) (interface{}, error) {
		gadget := args[0].(string)
		cmd := args[1].(string)

		var encoding string
		if len(args) > 2 {
			encoding = args[2].(string)
		}
		data := deserialization.GenerateJavaGadget(gadget, cmd, encoding)
		return data, nil
	},
}

// HelperFunctions returns the dsl helper functions
func HelperFunctions() map[string]govaluate.ExpressionFunction {
	return functions
}

// AddHelperFunction allows creation of additiona helper functions to be supported with templates
func AddHelperFunction(key string, value func(args ...interface{}) (interface{}, error)) error {
	if _, ok := functions[key]; !ok {
		functions[key] = value
		return nil
	}
	return errors.New("duplicate helper function key defined")
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func trimAll(s, cutset string) string {
	for _, c := range cutset {
		s = strings.ReplaceAll(s, string(c), "")
	}
	return s
}

func randSeq(base string, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rune(base[rand.Intn(len(base))])
	}
	return string(b)
}
