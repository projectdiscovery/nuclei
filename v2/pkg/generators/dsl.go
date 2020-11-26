package generators

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"math"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/nuclei/v2/pkg/collaborator"
	"github.com/spaolacci/murmur3"
)

const (
	withCutSetArgsSize   = 2
	withMaxRandArgsSize  = withCutSetArgsSize
	withBaseRandArgsSize = 3
)

var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
var numbers = "1234567890"

// HelperFunctions contains the dsl functions
func HelperFunctions() (functions map[string]govaluate.ExpressionFunction) {
	functions = make(map[string]govaluate.ExpressionFunction)

	// strings
	functions["len"] = func(args ...interface{}) (interface{}, error) {
		length := len(toString(args[0]))

		return float64(length), nil
	}

	functions["toupper"] = func(args ...interface{}) (interface{}, error) {
		return strings.ToUpper(toString(args[0])), nil
	}

	functions["tolower"] = func(args ...interface{}) (interface{}, error) {
		return strings.ToLower(toString(args[0])), nil
	}

	functions["replace"] = func(args ...interface{}) (interface{}, error) {
		return strings.ReplaceAll(toString(args[0]), toString(args[1]), toString(args[2])), nil
	}

	functions["replace_regex"] = func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(toString(args[1]))
		if err != nil {
			return nil, err
		}
		return compiled.ReplaceAllString(toString(args[0]), toString(args[2])), nil
	}

	functions["trim"] = func(args ...interface{}) (interface{}, error) {
		return strings.Trim(toString(args[0]), toString(args[2])), nil
	}

	functions["trimleft"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimLeft(toString(args[0]), toString(args[1])), nil
	}

	functions["trimright"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimRight(toString(args[0]), toString(args[1])), nil
	}

	functions["trimspace"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimSpace(toString(args[0])), nil
	}

	functions["trimprefix"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimPrefix(toString(args[0]), toString(args[1])), nil
	}

	functions["trimsuffix"] = func(args ...interface{}) (interface{}, error) {
		return strings.TrimSuffix(toString(args[0]), toString(args[1])), nil
	}

	functions["reverse"] = func(args ...interface{}) (interface{}, error) {
		return reverseString(toString(args[0])), nil
	}

	// encoding
	functions["base64"] = func(args ...interface{}) (interface{}, error) {
		sEnc := base64.StdEncoding.EncodeToString([]byte(toString(args[0])))

		return sEnc, nil
	}

	// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
	functions["base64_py"] = func(args ...interface{}) (interface{}, error) {
		sEnc := base64.StdEncoding.EncodeToString([]byte(toString(args[0])))

		return insertInto(sEnc, 76, '\n'), nil
	}

	functions["base64_decode"] = func(args ...interface{}) (interface{}, error) {
		return base64.StdEncoding.DecodeString(toString(args[0]))
	}

	functions["url_encode"] = func(args ...interface{}) (interface{}, error) {
		return url.PathEscape(toString(args[0])), nil
	}

	functions["url_decode"] = func(args ...interface{}) (interface{}, error) {
		return url.PathUnescape(toString(args[0]))
	}

	functions["hex_encode"] = func(args ...interface{}) (interface{}, error) {
		return hex.EncodeToString([]byte(toString(args[0]))), nil
	}

	functions["hex_decode"] = func(args ...interface{}) (interface{}, error) {
		hx, _ := hex.DecodeString(toString(args[0]))
		return string(hx), nil
	}

	functions["html_escape"] = func(args ...interface{}) (interface{}, error) {
		return html.EscapeString(toString(args[0])), nil
	}

	functions["html_unescape"] = func(args ...interface{}) (interface{}, error) {
		return html.UnescapeString(toString(args[0])), nil
	}

	// hashing
	functions["md5"] = func(args ...interface{}) (interface{}, error) {
		hash := md5.Sum([]byte(toString(args[0])))

		return hex.EncodeToString(hash[:]), nil
	}

	functions["sha256"] = func(args ...interface{}) (interface{}, error) {
		h := sha256.New()
		_, err := h.Write([]byte(toString(args[0])))

		if err != nil {
			return nil, err
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	functions["sha1"] = func(args ...interface{}) (interface{}, error) {
		h := sha1.New()
		_, err := h.Write([]byte(toString(args[0])))

		if err != nil {
			return nil, err
		}

		return hex.EncodeToString(h.Sum(nil)), nil
	}

	functions["mmh3"] = func(args ...interface{}) (interface{}, error) {
		return fmt.Sprintf("%d", int32(murmur3.Sum32WithSeed([]byte(toString(args[0])), 0))), nil
	}

	// search
	functions["contains"] = func(args ...interface{}) (interface{}, error) {
		return strings.Contains(toString(args[0]), toString(args[1])), nil
	}

	functions["regex"] = func(args ...interface{}) (interface{}, error) {
		compiled, err := regexp.Compile(toString(args[0]))
		if err != nil {
			return nil, err
		}

		return compiled.MatchString(toString(args[1])), nil
	}

	// random generators
	functions["rand_char"] = func(args ...interface{}) (interface{}, error) {
		chars := letters + numbers
		bad := ""
		if len(args) >= 1 {
			chars = toString(args[0])
		}
		if len(args) >= withCutSetArgsSize {
			bad = toString(args[1])
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
		if len(args) >= withCutSetArgsSize {
			bad = toString(args[1])
		}
		if len(args) >= withBaseRandArgsSize {
			base = toString(args[2])
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
		if len(args) >= withCutSetArgsSize {
			bad = toString(args[1])
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
		if len(args) >= withCutSetArgsSize {
			bad = toString(args[1])
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
		if len(args) >= withCutSetArgsSize {
			bad = toString(args[1])
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
		if len(args) >= withMaxRandArgsSize {
			max = args[1].(int)
		}

		return rand.Intn(max-min) + min, nil
	}

	// Time Functions
	functions["waitfor"] = func(args ...interface{}) (interface{}, error) {
		seconds := args[0].(float64)
		time.Sleep(time.Duration(seconds) * time.Second)
		return true, nil
	}

	// Collaborator
	functions["collab"] = func(args ...interface{}) (interface{}, error) {
		// check if collaborator contains a specific pattern
		return collaborator.DefaultCollaborator.Has(toString(args[0])), nil
	}

	return functions
}
