package generators

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html"
	"math"
	"math/rand"
	"net/url"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/reusee/mmh3"
)

var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
var numbers = "1234567890"

// HelperFunctions contains the dsl functions
func HelperFunctions() (functions map[string]govaluate.ExpressionFunction) {
	functions = make(map[string]govaluate.ExpressionFunction)

	// strings
	functions["len"] = func(args ...interface{}) (interface{}, error) {
		length := len(args[0].(string))

		return float64(length), nil
	}

	functions["toupper"] = func(args ...interface{}) (interface{}, error) {
		return strings.ToUpper(args[0].(string)), nil
	}

	functions["tolower"] = func(args ...interface{}) (interface{}, error) {
		return strings.ToLower(args[0].(string)), nil
	}

	functions["replace"] = func(args ...interface{}) (interface{}, error) {
		return strings.ReplaceAll(args[0].(string), args[1].(string), args[2].(string)), nil
	}

	functions["trim"] = func(args ...interface{}) (interface{}, error) {
		return strings.Trim(args[0].(string), args[2].(string)), nil
	}

	functions["trimleft"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimLeft(args[0].(string), args[1].(string)), nil
	}

	functions["trimright"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimRight(args[0].(string), args[1].(string)), nil
	}

	functions["trimspace"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimSpace(args[0].(string)), nil
	}

	functions["trimprefix"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimPrefix(args[0].(string), args[1].(string)), nil
	}

	functions["trimsuffix"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimSuffix(args[0].(string), args[1].(string)), nil
	}

	functions["reverse"] = func(args ...interface{}) (interface{}, error) {
		return reverseString(args[0].(string)), nil
	}

	// encoding
	functions["base64"] = func(args ...interface{}) (interface{}, error) {
		sEnc := base64.StdEncoding.EncodeToString([]byte(args[0].(string)))

		return sEnc, nil
	}

	functions["base64_decode"] = func(args ...interface{}) (interface{}, error) {
		return base64.StdEncoding.DecodeString(args[0].(string))
	}

	functions["url_encode"] = func(args ...interface{}) (interface{}, error) {
		return url.PathEscape(args[0].(string)), nil
	}

	functions["url_decode"] = func(args ...interface{}) (interface{}, error) {
		return url.PathUnescape(args[0].(string))
	}

	functions["hex_encode"] = func(args ...interface{}) (interface{}, error) {
		return hex.EncodeToString([]byte(args[0].(string))), nil
	}

	functions["hex_decode"] = func(args ...interface{}) (interface{}, error) {
		hx, _ := hex.DecodeString(args[0].(string))
		return string(hx), nil
	}

	functions["html_escape"] = func(args ...interface{}) (interface{}, error) {
		return html.EscapeString(args[0].(string)), nil
	}

	functions["html_unescape"] = func(args ...interface{}) (interface{}, error) {
		return html.UnescapeString(args[0].(string)), nil
	}

	// hashing
	functions["md5"] = func(args ...interface{}) (interface{}, error) {
		hash := md5.Sum([]byte(args[0].(string)))

		return hex.EncodeToString(hash[:]), nil
	}

	functions["sha256"] = func(args ...interface{}) (interface{}, error) {
		h := sha256.New()
		_, err := h.Write([]byte(args[0].(string)))

		if err != nil {
			return nil, err
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	functions["sha1"] = func(args ...interface{}) (interface{}, error) {
		h := sha1.New()
		_, err := h.Write([]byte(args[0].(string)))

		if err != nil {
			return nil, err
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	functions["mmh3"] = func(args ...interface{}) (interface{}, error) {
		h := mmh3.New128()
		_, err := h.Write([]byte(args[0].(string)))
		if err != nil {
			return nil, err
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	// search
	functions["contains"] = func(args ...interface{}) (interface{}, error) {
		return strings.Contains(args[0].(string), args[1].(string)), nil
	}

	functions["regex"] = func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(args[0].(string))
		if err != nil {
			return nil, err
		}

		return compiled.MatchString(args[1].(string)), nil
	}

	// random generators
	functions["rand_char"] = func(args ...interface{}) (interface{}, error) {
		chars := letters + numbers
		bad := ""
		if len(args) >= 1 {
			chars = args[0].(string)
		}
		if len(args) >= 2 {
			bad = args[1].(string)
		}

		chars = TrimAll(chars, bad)

		return chars[rand.Intn(len(chars))], nil
	}

	functions["rand_base"] = func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		base := letters + numbers

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= 2 {
			bad = args[1].(string)
		}
		if len(args) >= 3 {
			base = args[2].(string)
		}

		base = TrimAll(base, bad)

		return RandSeq(base, l), nil
	}

	functions["rand_text_alphanumeric"] = func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		chars := letters + numbers

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= 2 {
			bad = args[1].(string)
		}

		chars = TrimAll(chars, bad)

		return RandSeq(chars, l), nil
	}

	functions["rand_text_alpha"] = func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		chars := letters

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= 2 {
			bad = args[1].(string)
		}

		chars = TrimAll(chars, bad)

		return RandSeq(chars, l), nil
	}

	functions["rand_text_numeric"] = func(args ...interface{}) (interface{}, error) {
		l := 0
		bad := ""
		chars := numbers

		if len(args) >= 1 {
			l = args[0].(int)
		}
		if len(args) >= 2 {
			bad = args[1].(string)
		}

		chars = TrimAll(chars, bad)

		return RandSeq(chars, l), nil
	}

	functions["rand_int"] = func(args ...interface{}) (interface{}, error) {
		min := 0
		max := math.MaxInt32

		if len(args) >= 1 {
			min = args[0].(int)
		}
		if len(args) >= 2 {
			max = args[1].(int)
		}

		return rand.Intn(max-min) + min, nil
	}

	return functions
}
