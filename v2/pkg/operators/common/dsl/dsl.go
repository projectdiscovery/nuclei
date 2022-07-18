package dsl

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"html"
	"io"
	"math"
	"math/rand"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/Knetic/govaluate"
	"github.com/asaskevich/govalidator"
	"github.com/hashicorp/go-version"
	"github.com/logrusorgru/aurora"
	"github.com/spaolacci/murmur3"

	uuid "github.com/satori/go.uuid"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/helpers/deserialization"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/randomip"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

const (
	numbers = "1234567890"
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var invalidDslFunctionError = errors.New("invalid DSL function signature")
var invalidDslFunctionMessageTemplate = "%w. correct method signature %q"

var dslFunctions map[string]dslFunction

var functionSignaturePattern = regexp.MustCompile(`(\w+)\s*\((?:([\w\d,\s]+)\s+([.\w\d{}&*]+))?\)([\s.\w\d{}&*]+)?`)
var dateFormatRegex = regexp.MustCompile("%([A-Za-z])")

type dslFunction struct {
	signature   string
	expressFunc govaluate.ExpressionFunction
}

func init() {
	tempDslFunctions := map[string]func(string) dslFunction{
		"len": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			length := len(types.ToString(args[0]))
			return float64(length), nil
		}),
		"to_upper": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToUpper(types.ToString(args[0])), nil
		}),
		"to_lower": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToLower(types.ToString(args[0])), nil
		}),
		"repeat": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			count, err := strconv.Atoi(types.ToString(args[1]))
			if err != nil {
				return nil, invalidDslFunctionError
			}
			return strings.Repeat(types.ToString(args[0]), count), nil
		}),
		"replace": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			return strings.ReplaceAll(types.ToString(args[0]), types.ToString(args[1]), types.ToString(args[2])), nil
		}),
		"replace_regex": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			compiled, err := regexp.Compile(types.ToString(args[1]))
			if err != nil {
				return nil, err
			}
			return compiled.ReplaceAllString(types.ToString(args[0]), types.ToString(args[2])), nil
		}),
		"trim": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.Trim(types.ToString(args[0]), types.ToString(args[1])), nil
		}),
		"trim_left": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimLeft(types.ToString(args[0]), types.ToString(args[1])), nil
		}),
		"trim_right": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimRight(types.ToString(args[0]), types.ToString(args[1])), nil
		}),
		"trim_space": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.TrimSpace(types.ToString(args[0])), nil
		}),
		"trim_prefix": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimPrefix(types.ToString(args[0]), types.ToString(args[1])), nil
		}),
		"trim_suffix": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.TrimSuffix(types.ToString(args[0]), types.ToString(args[1])), nil
		}),
		"reverse": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return reverseString(types.ToString(args[0])), nil
		}),
		"base64": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return base64.StdEncoding.EncodeToString([]byte(types.ToString(args[0]))), nil
		}),
		"gzip": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			buffer := &bytes.Buffer{}
			writer := gzip.NewWriter(buffer)
			if _, err := writer.Write([]byte(args[0].(string))); err != nil {
				_ = writer.Close()
				return "", err
			}
			_ = writer.Close()

			return buffer.String(), nil
		}),
		"gzip_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			reader, err := gzip.NewReader(strings.NewReader(args[0].(string)))
			if err != nil {
				return "", err
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				_ = reader.Close()
				return "", err
			}
			_ = reader.Close()
			return string(data), nil
		}),
		"zlib": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			buffer := &bytes.Buffer{}
			writer := zlib.NewWriter(buffer)
			if _, err := writer.Write([]byte(args[0].(string))); err != nil {
				_ = writer.Close()
				return "", err
			}
			_ = writer.Close()

			return buffer.String(), nil
		}),
		"zlib_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			reader, err := zlib.NewReader(strings.NewReader(args[0].(string)))
			if err != nil {
				return "", err
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				_ = reader.Close()
				return "", err
			}
			_ = reader.Close()
			return string(data), nil
		}),
		"date_time": makeDslWithOptionalArgsFunction(
			"(dateTimeFormat string, optionalUnixTime interface{}) string",
			func(arguments ...interface{}) (interface{}, error) {
				dateTimeFormat := types.ToString(arguments[0])
				dateTimeFormatFragment := dateFormatRegex.FindAllStringSubmatch(dateTimeFormat, -1)

				argumentsSize := len(arguments)
				if argumentsSize < 1 && argumentsSize > 2 {
					return nil, errors.New("invalid number of arguments")
				}

				currentTime, err := getCurrentTimeFromUserInput(arguments)
				if err != nil {
					return nil, err
				}

				if len(dateTimeFormatFragment) > 0 {
					return doSimpleTimeFormat(dateTimeFormatFragment, currentTime, dateTimeFormat)
				} else {
					return currentTime.Format(dateTimeFormat), nil
				}
			},
		),
		"base64_py": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
			stdBase64 := base64.StdEncoding.EncodeToString([]byte(types.ToString(args[0])))
			return deserialization.InsertInto(stdBase64, 76, '\n'), nil
		}),
		"base64_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			data, err := base64.StdEncoding.DecodeString(types.ToString(args[0]))
			return string(data), err
		}),
		"url_encode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return url.QueryEscape(types.ToString(args[0])), nil
		}),
		"url_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return url.QueryUnescape(types.ToString(args[0]))
		}),
		"hex_encode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return hex.EncodeToString([]byte(types.ToString(args[0]))), nil
		}),
		"hex_decode": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			decodeString, err := hex.DecodeString(types.ToString(args[0]))
			return string(decodeString), err
		}),
		"hmac": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			hashAlgorithm := args[0]
			data := args[1].(string)
			secretKey := args[2].(string)

			var hashFunction func() hash.Hash
			switch hashAlgorithm {
			case "sha1", "sha-1":
				hashFunction = sha1.New
			case "sha256", "sha-256":
				hashFunction = sha256.New
			default:
				return nil, fmt.Errorf("unsupported hash algorithm: '%s'", hashAlgorithm)
			}

			h := hmac.New(hashFunction, []byte(secretKey))
			h.Write([]byte(data))
			return hex.EncodeToString(h.Sum(nil)), nil
		}),
		"html_escape": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return html.EscapeString(types.ToString(args[0])), nil
		}),
		"html_unescape": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return html.UnescapeString(types.ToString(args[0])), nil
		}),
		"md5": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(md5.New(), types.ToString(args[0]))
		}),
		"sha256": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(sha256.New(), types.ToString(args[0]))
		}),
		"sha1": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return toHexEncodedHash(sha1.New(), types.ToString(args[0]))
		}),
		"mmh3": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			hasher := murmur3.New32WithSeed(0)
			hasher.Write([]byte(fmt.Sprint(args[0])))
			return fmt.Sprintf("%d", int32(hasher.Sum32())), nil
		}),
		"contains": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			return strings.Contains(types.ToString(args[0]), types.ToString(args[1])), nil
		}),
		"concat": makeDslWithOptionalArgsFunction(
			"(args ...interface{}) string",
			func(arguments ...interface{}) (interface{}, error) {
				builder := &strings.Builder{}
				for _, argument := range arguments {
					builder.WriteString(types.ToString(argument))
				}
				return builder.String(), nil
			},
		),
		"join": makeDslWithOptionalArgsFunction(
			"(separator string, elements ...interface{}) string",
			func(arguments ...interface{}) (interface{}, error) {
				argumentsSize := len(arguments)
				if argumentsSize < 2 {
					return nil, errors.New("incorrect number of arguments received")
				}

				separator := types.ToString(arguments[0])
				elements := arguments[1:argumentsSize]

				stringElements := make([]string, 0, argumentsSize)
				for _, element := range elements {
					stringElements = append(stringElements, types.ToString(element))
				}
				return strings.Join(stringElements, separator), nil
			},
		),
		"regex": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			compiled, err := regexp.Compile(types.ToString(args[0]))
			if err != nil {
				return nil, err
			}
			return compiled.MatchString(types.ToString(args[1])), nil
		}),
		"remove_bad_chars": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			input := types.ToString(args[0])
			badChars := types.ToString(args[1])
			return trimAll(input, badChars), nil
		}),
		"rand_char": makeDslWithOptionalArgsFunction(
			"(optionalCharSet string) string",
			func(args ...interface{}) (interface{}, error) {
				charSet := letters + numbers

				argSize := len(args)
				if argSize != 0 && argSize != 1 {
					return nil, invalidDslFunctionError
				}

				if argSize >= 1 {
					inputCharSet := types.ToString(args[0])
					if strings.TrimSpace(inputCharSet) != "" {
						charSet = inputCharSet
					}
				}

				return string(charSet[rand.Intn(len(charSet))]), nil
			},
		),
		"rand_base": makeDslWithOptionalArgsFunction(
			"(length uint, optionalCharSet string) string",
			func(args ...interface{}) (interface{}, error) {
				var length int
				charSet := letters + numbers

				argSize := len(args)
				if argSize < 1 || argSize > 3 {
					return nil, invalidDslFunctionError
				}

				length = int(args[0].(float64))

				if argSize == 2 {
					inputCharSet := types.ToString(args[1])
					if strings.TrimSpace(inputCharSet) != "" {
						charSet = inputCharSet
					}
				}
				return randSeq(charSet, length), nil
			},
		),
		"rand_text_alphanumeric": makeDslWithOptionalArgsFunction(
			"(length uint, optionalBadChars string) string",
			func(args ...interface{}) (interface{}, error) {
				length := 0
				badChars := ""

				argSize := len(args)
				if argSize != 1 && argSize != 2 {
					return nil, invalidDslFunctionError
				}

				length = int(args[0].(float64))

				if argSize == 2 {
					badChars = types.ToString(args[1])
				}
				chars := trimAll(letters+numbers, badChars)
				return randSeq(chars, length), nil
			},
		),
		"rand_text_alpha": makeDslWithOptionalArgsFunction(
			"(length uint, optionalBadChars string) string",
			func(args ...interface{}) (interface{}, error) {
				var length int
				badChars := ""

				argSize := len(args)
				if argSize != 1 && argSize != 2 {
					return nil, invalidDslFunctionError
				}

				length = int(args[0].(float64))

				if argSize == 2 {
					badChars = types.ToString(args[1])
				}
				chars := trimAll(letters, badChars)
				return randSeq(chars, length), nil
			},
		),
		"rand_text_numeric": makeDslWithOptionalArgsFunction(
			"(length uint, optionalBadNumbers string) string",
			func(args ...interface{}) (interface{}, error) {
				argSize := len(args)
				if argSize != 1 && argSize != 2 {
					return nil, invalidDslFunctionError
				}

				length := int(args[0].(float64))
				badNumbers := ""

				if argSize == 2 {
					badNumbers = types.ToString(args[1])
				}

				chars := trimAll(numbers, badNumbers)
				return randSeq(chars, length), nil
			},
		),
		"rand_int": makeDslWithOptionalArgsFunction(
			"(optionalMin, optionalMax uint) int",
			func(args ...interface{}) (interface{}, error) {
				argSize := len(args)
				if argSize > 2 {
					return nil, invalidDslFunctionError
				}

				min := 0
				max := math.MaxInt32

				if argSize >= 1 {
					min = int(args[0].(float64))
				}
				if argSize == 2 {
					max = int(args[1].(float64))
				}
				return rand.Intn(max-min) + min, nil
			},
		),
		"rand_ip": makeDslWithOptionalArgsFunction(
			"(cidr ...string) string",
			func(args ...interface{}) (interface{}, error) {
				if len(args) == 0 {
					return nil, invalidDslFunctionError
				}
				var cidrs []string
				for _, arg := range args {
					cidrs = append(cidrs, arg.(string))
				}
				return randomip.GetRandomIPWithCidr(cidrs...)
			}),
		"generate_java_gadget": makeDslFunction(3, func(args ...interface{}) (interface{}, error) {
			gadget := args[0].(string)
			cmd := args[1].(string)
			encoding := args[2].(string)
			data := deserialization.GenerateJavaGadget(gadget, cmd, encoding)
			return data, nil
		}),
		"unix_time": makeDslWithOptionalArgsFunction(
			"(optionalSeconds uint) float64",
			func(args ...interface{}) (interface{}, error) {
				seconds := 0

				argSize := len(args)
				if argSize != 0 && argSize != 1 {
					return nil, invalidDslFunctionError
				} else if argSize == 1 {
					seconds = int(args[0].(float64))
				}

				offset := time.Now().Add(time.Duration(seconds) * time.Second)
				return float64(offset.Unix()), nil
			},
		),
		"wait_for": makeDslWithOptionalArgsFunction(
			"(seconds uint)",
			func(args ...interface{}) (interface{}, error) {
				if len(args) != 1 {
					return nil, invalidDslFunctionError
				}
				seconds := args[0].(float64)
				time.Sleep(time.Duration(seconds) * time.Second)
				return true, nil
			},
		),
		"compare_versions": makeDslWithOptionalArgsFunction(
			"(firstVersion, constraints ...string) bool",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 2 {
					return nil, invalidDslFunctionError
				}

				firstParsed, parseErr := version.NewVersion(types.ToString(args[0]))
				if parseErr != nil {
					return nil, parseErr
				}

				var versionConstraints []string
				for _, constraint := range args[1:] {
					versionConstraints = append(versionConstraints, types.ToString(constraint))
				}
				constraint, constraintErr := version.NewConstraint(strings.Join(versionConstraints, ","))
				if constraintErr != nil {
					return nil, constraintErr
				}
				result := constraint.Check(firstParsed)
				return result, nil
			},
		),
		"print_debug": makeDslWithOptionalArgsFunction(
			"(args ...interface{})",
			func(args ...interface{}) (interface{}, error) {
				if len(args) < 1 {
					return nil, invalidDslFunctionError
				}
				gologger.Info().Msgf("print_debug value: %s", fmt.Sprint(args))
				return true, nil
			},
		),
		"substr": makeDslWithOptionalArgsFunction(
			"(args ...interface{})",
			func(args ...interface{}) (interface{}, error) {
				argStr := types.ToString(args[0])
				a1 := types.ToString(args[1])
				if len(args) == 2 {
					n1, err := strconv.Atoi(a1)
					if nil != err {
						return nil, err
					}
					return argStr[n1:], nil
				} else if len(args) == 3 {
					a2 := types.ToString(args[2])
					n1, err1 := strconv.Atoi(a1)
					if nil != err1 {
						return nil, err1
					}
					n2, err := strconv.Atoi(a2)
					if nil != err {
						return nil, err
					}
					return argStr[n1:n2], nil
				}
				return nil, nil
			},
		),
		"to_number": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			argStr := types.ToString(args[0])
			if govalidator.IsInt(argStr) {
				sint, err := strconv.Atoi(argStr)
				return float64(sint), err
			} else if govalidator.IsFloat(argStr) {
				sint, err := strconv.ParseFloat(argStr, 64)
				return float64(sint), err
			}
			return nil, errors.Errorf("%v could not be converted to int", argStr)
		}),
		"to_string": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return types.ToString(args[0]), nil
		}),
		"dec_to_hex": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			if number, ok := args[0].(float64); ok {
				hexNum := strconv.FormatInt(int64(number), 16)
				return types.ToString(hexNum), nil
			}
			return nil, fmt.Errorf("invalid number: %T", args[0])
		}),
		"aes_cbc": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			key := args[0].(string)
			value := args[1].(string)
			Content := []byte(value)
			block, _ := aes.NewCipher([]byte(key))
			blockSize := block.BlockSize()
			n := blockSize - len(Content)%blockSize
			temp := bytes.Repeat([]byte{byte(n)}, n)
			Content = append(Content, temp...)

			iv := uuid.NewV4().Bytes()
			blockMode := cipher.NewCBCEncrypter(block, iv)
			cipherText := make([]byte, len(Content))
			blockMode.CryptBlocks(cipherText, Content)
			return append(iv[:], cipherText[:]...), nil
		}),
		"aes_gcm": makeDslFunction(2, func(args ...interface{}) (interface{}, error) {
			key := args[0].(string)
			value := args[1].(string)

			c, err := aes.NewCipher([]byte(key))
			if nil != err {
				return "", err
			}
			gcm, err := cipher.NewGCM(c)
			if nil != err {
				return "", err
			}

			nonce := make([]byte, gcm.NonceSize())
			if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
				return "", err
			}
			data := gcm.Seal(nonce, nonce, []byte(value), nil)
			return data, nil
		}),
	}

	dslFunctions = make(map[string]dslFunction, len(tempDslFunctions))
	for funcName, dslFunc := range tempDslFunctions {
		dslFunctions[funcName] = dslFunc(funcName)
	}
}

func makeDslWithOptionalArgsFunction(signaturePart string, dslFunctionLogic govaluate.ExpressionFunction) func(functionName string) dslFunction {
	return func(functionName string) dslFunction {
		return dslFunction{
			functionName + signaturePart,
			dslFunctionLogic,
		}
	}
}

func makeDslFunction(numberOfParameters int, dslFunctionLogic govaluate.ExpressionFunction) func(functionName string) dslFunction {
	return func(functionName string) dslFunction {
		signature := functionName + createSignaturePart(numberOfParameters)
		return dslFunction{
			signature,
			func(args ...interface{}) (interface{}, error) {
				if len(args) != numberOfParameters {
					return nil, fmt.Errorf(invalidDslFunctionMessageTemplate, invalidDslFunctionError, signature)
				}
				return dslFunctionLogic(args...)
			},
		}
	}
}

func createSignaturePart(numberOfParameters int) string {
	params := make([]string, 0, numberOfParameters)
	for i := 1; i <= numberOfParameters; i++ {
		params = append(params, "arg"+strconv.Itoa(i))
	}
	return fmt.Sprintf("(%s interface{}) interface{}", strings.Join(params, ", "))
}

// HelperFunctions returns the dsl helper functions
func HelperFunctions() map[string]govaluate.ExpressionFunction {
	helperFunctions := make(map[string]govaluate.ExpressionFunction, len(dslFunctions))

	for functionName, dslFunction := range dslFunctions {
		helperFunctions[functionName] = dslFunction.expressFunc
		helperFunctions[strings.ReplaceAll(functionName, "_", "")] = dslFunction.expressFunc // for backwards compatibility
	}

	return helperFunctions
}

// AddHelperFunction allows creation of additional helper functions to be supported with templates
//goland:noinspection GoUnusedExportedFunction
func AddHelperFunction(key string, value func(args ...interface{}) (interface{}, error)) error {
	if _, ok := dslFunctions[key]; !ok {
		dslFunction := dslFunctions[key]
		dslFunction.signature = "(args ...interface{}) interface{}"
		dslFunction.expressFunc = value
		return nil
	}
	return errors.New("duplicate helper function key defined")
}

func GetPrintableDslFunctionSignatures(noColor bool) string {
	aggregateSignatures := func(values []string) string {
		sort.Strings(values)

		builder := &strings.Builder{}
		for _, value := range values {
			builder.WriteRune('\t')
			builder.WriteString(value)
			builder.WriteRune('\n')
		}
		return builder.String()
	}

	if noColor {
		return aggregateSignatures(getDslFunctionSignatures())
	}
	return aggregateSignatures(colorizeDslFunctionSignatures())
}

func getDslFunctionSignatures() []string {
	result := make([]string, 0, len(dslFunctions))

	for _, dslFunction := range dslFunctions {
		result = append(result, dslFunction.signature)
	}

	return result
}

func colorizeDslFunctionSignatures() []string {
	signatures := getDslFunctionSignatures()

	colorToOrange := func(value string) string {
		return aurora.Index(208, value).String()
	}

	result := make([]string, 0, len(signatures))

	for _, signature := range signatures {
		subMatchSlices := functionSignaturePattern.FindAllStringSubmatch(signature, -1)
		if len(subMatchSlices) != 1 {
			// TODO log when #1166 is implemented
			return signatures
		}
		matches := subMatchSlices[0]
		if len(matches) != 5 {
			// TODO log when #1166 is implemented
			return signatures
		}

		functionParameters := strings.Split(matches[2], ",")

		var coloredParameterAndTypes []string
		for _, functionParameter := range functionParameters {
			functionParameter = strings.TrimSpace(functionParameter)
			paramAndType := strings.Split(functionParameter, " ")
			if len(paramAndType) == 1 {
				coloredParameterAndTypes = append(coloredParameterAndTypes, paramAndType[0])
			} else if len(paramAndType) == 2 {
				coloredParameterAndTypes = append(coloredParameterAndTypes, fmt.Sprintf("%s %s", paramAndType[0], colorToOrange(paramAndType[1])))
			}
		}

		highlightedParams := strings.TrimSpace(fmt.Sprintf("%s %s", strings.Join(coloredParameterAndTypes, ", "), colorToOrange(matches[3])))
		colorizedDslSignature := fmt.Sprintf("%s(%s)%s", aurora.BrightYellow(matches[1]).String(), highlightedParams, colorToOrange(matches[4]))

		result = append(result, colorizedDslSignature)
	}

	return result
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

func toHexEncodedHash(hashToUse hash.Hash, data string) (interface{}, error) {
	if _, err := hashToUse.Write([]byte(data)); err != nil {
		return nil, err
	}
	return hex.EncodeToString(hashToUse.Sum(nil)), nil
}

func doSimpleTimeFormat(dateTimeFormatFragment [][]string, currentTime time.Time, dateTimeFormat string) (interface{}, error) {
	for _, currentFragment := range dateTimeFormatFragment {
		if len(currentFragment) < 2 {
			continue
		}
		prefixedFormatFragment := currentFragment[0]
		switch currentFragment[1] {
		case "Y", "y":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Year())
		case "M":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, int(currentTime.Month()))
		case "D", "d":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Day())
		case "H", "h":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Hour())
		case "m":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Minute())
		case "S", "s":
			dateTimeFormat = formatDateTime(dateTimeFormat, prefixedFormatFragment, currentTime.Second())
		default:
			return nil, fmt.Errorf("invalid date time format string: %s", prefixedFormatFragment)
		}
	}
	return dateTimeFormat, nil
}

func getCurrentTimeFromUserInput(arguments []interface{}) (time.Time, error) {
	var currentTime time.Time
	if len(arguments) == 2 {
		switch inputUnixTime := arguments[1].(type) {
		case time.Time:
			currentTime = inputUnixTime
		case string:
			unixTime, err := strconv.ParseInt(inputUnixTime, 10, 64)
			if err != nil {
				return time.Time{}, errors.New("invalid argument type")
			}
			currentTime = time.Unix(unixTime, 0)
		case int64, float64:
			currentTime = time.Unix(int64(inputUnixTime.(float64)), 0)
		default:
			return time.Time{}, errors.New("invalid argument type")
		}
	} else {
		currentTime = time.Now()
	}
	return currentTime, nil
}

func formatDateTime(inputFormat string, matchValue string, timeFragment int) string {
	return strings.ReplaceAll(inputFormat, matchValue, appendSingleDigitZero(strconv.Itoa(timeFragment)))
}

// appendSingleDigitZero appends zero at front if not exists already doing two digit padding
func appendSingleDigitZero(value string) string {
	if len(value) == 1 && (!strings.HasPrefix(value, "0") || value == "0") {
		builder := &strings.Builder{}
		builder.WriteRune('0')
		builder.WriteString(value)
		newVal := builder.String()
		return newVal
	}
	return value
}
