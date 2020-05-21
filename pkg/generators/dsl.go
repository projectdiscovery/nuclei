package generators

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
)

// HelperFunctions contains the dsl functions
func HelperFunctions() (functions map[string]govaluate.ExpressionFunction) {
	functions = make(map[string]govaluate.ExpressionFunction)
	// strings
	functions["len"] = func(args ...interface{}) (interface{}, error) {
		length := len(args[0].(string))
		return (float64)(length), nil
	}
	functions["toupper"] = func(args ...interface{}) (interface{}, error) {
		return strings.ToUpper(args[0].(string)), nil
	}
	functions["tolower"] = func(args ...interface{}) (interface{}, error) {
		return strings.ToLower(args[0].(string)), nil
	}
	functions["replace"] = func(args ...interface{}) (interface{}, error) {
		return strings.Replace(args[0].(string), args[1].(string), args[2].(string), -1), nil
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
		sEnc := base64.StdEncoding.EncodeToString([]byte(args[0].(string)))
		return sEnc, nil
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
		h.Write([]byte(args[0].(string)))
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	functions["sha1"] = func(args ...interface{}) (interface{}, error) {
		h := sha1.New()
		h.Write([]byte(args[0].(string)))
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

	return
}
