package fuzzing

import (
	"io"
	"strconv"
	"strings"

	"github.com/morikuni/accessor"
)

// Transform contains the ways described to transform  a document a single
// time. Each transformation will be done one by one leading to fuzzing
// of all request parts in a synchronous manner.
type Transform struct {
	Part  string
	Key   string
	Value string
}

// CreateTransform creates a transform structure describing how to
// change the request one by one to meet all of user's fuzzing conditions.
func CreateTransform(req *NormalizedRequest, options *AnalyzerOptions) []*Transform {
	transforms := []*Transform{}

	parts := make(map[string]struct{})

	if len(options.Parts) == 0 {
		parts["default"] = struct{}{}
	} else {
		for _, part := range options.Parts {
			parts[part] = struct{}{}
		}
	}
	if _, ok := parts["default"]; ok {
		parts["body"] = struct{}{}
		parts["query-values"] = struct{}{}
		parts["headers"] = struct{}{}
		delete(parts, "default")
	}
	if _, ok := parts["all"]; ok {
		parts["path"] = struct{}{}
		parts["cookies"] = struct{}{}
		parts["body"] = struct{}{}
		parts["query-values"] = struct{}{}
		parts["headers"] = struct{}{}
		delete(parts, "all")
	}

	if len(options.PartsConfig) == 0 {
		options.PartsConfig = defaultPartsConfig
	} else {
		found, ok := options.PartsConfig["headers"]
		if ok && len(found) >= 1 {
			if found[0].Invalid != nil {
				for _, v := range defaultIgnoredHeaderKeys {
					found[0].Invalid.Keys = append(found[0].Invalid.Keys, v)
				}
			} else {
				found[0].Invalid = &AnalyerPartsConfigMatcher{Keys: defaultIgnoredHeaderKeys}
			}
		}
	}

	builder := &strings.Builder{}
	builder.Grow(len(req.Path))

	// If we have a body template with no append/replace, only do a blank replacement.
	if options.BodyTemplate != "" && len(options.Append) == 0 && len(options.Replace) == 0 {
		transforms = append(transforms, &Transform{})
	}
	matched := options.Match("path", req.Path, "")
	if _, ok := parts["path"]; ok && matched {
		transforms = options.transformPath(req.Path, transforms)
	}
	if _, ok := parts["query-values"]; ok {
		transforms = options.transformMapStringSlice("query-values", req.QueryValues, transforms)
	}
	if _, ok := parts["headers"]; ok {
		transforms = options.transformMapStringSlice("headers", req.Headers, transforms)
	}
	if _, ok := parts["cookies"]; ok {
		transforms = options.transformMapStringSlice("cookies", req.Cookies, transforms)
	}
	if _, ok := parts["body"]; ok {
		if len(req.FormData) > 0 && (len(options.BodyType) == 0 || strings.EqualFold(options.BodyType, "form")) {
			transforms = options.transformMapStringSlice("body", req.FormData, transforms)
		}
		if len(req.MultipartBody) > 0 {
			multipartData := make(map[string][]string)
			for k, v := range req.MultipartBody {
				multipartData[k] = []string{v.Value}
			}
			transforms = options.transformMapStringSlice("body", multipartData, transforms)
		}
		if req.JSONData != nil && (len(options.BodyType) == 0 || strings.EqualFold(options.BodyType, "json")) {
			transforms = options.transformInterface("body", req.JSONData, transforms)
		}
		if req.XMLData != nil && (len(options.BodyType) == 0 || strings.EqualFold(options.BodyType, "xml")) {
			transforms = options.transformInterface("body", req.XMLData, transforms)
		}
	}
	return transforms
}

// transformPath returns the transforms for a path variable
func (o *AnalyzerOptions) transformPath(data string, transforms []*Transform) []*Transform {
	builder := &strings.Builder{}

	for _, v := range o.Append {
		builder.Reset()
		builder.WriteString(data)
		if !strings.HasSuffix(data, "/") {
			builder.WriteString("/")
		}
		builder.WriteString(v)

		transforms = append(transforms, &Transform{
			Part:  "path",
			Value: builder.String(),
		})
	}
	for _, v := range o.Replace {
		builder.Reset()
		builder.WriteString(data[:strings.LastIndex(data, "/")+1])
		builder.WriteString(v)

		transforms = append(transforms, &Transform{
			Part:  "path",
			Value: builder.String(),
		})
	}
	return transforms
}

// transformInterface reduces a interface to a set of transformations
func (o *AnalyzerOptions) transformInterface(part string, data interface{}, transforms []*Transform) []*Transform {
	builder := &strings.Builder{}

	if values, ok := data.([]interface{}); ok {
		var data string
		if len(values) > 0 {
			data = values[0].(string)
		}
		if !o.Match(part, "", data) {
			return nil
		}

		for _, value := range o.Append {
			builder.Reset()
			builder.WriteString(data)
			builder.WriteString(value)

			transforms = append(transforms, &Transform{
				Part:  part,
				Value: builder.String(),
			})
		}
		for _, value := range o.Replace {
			builder.Reset()
			builder.WriteString(value)

			transforms = append(transforms, &Transform{
				Part:  part,
				Value: builder.String(),
			})
		}
		return transforms
	}

	acc, err := accessor.NewAccessor(data)
	if err != nil {
		return transforms
	}
	sameNames := make(map[string]struct{})
	_ = acc.Foreach(func(path accessor.Path, data interface{}) error {
		if _, ok := data.(string); !ok {
			return nil
		}

		pathString := path.String()
		if strings.Count(pathString, "/") == o.MaxDepth {
			return io.EOF
		}
		final := pathString[:strings.LastIndex(pathString, "/")]
		preFinal := pathString[strings.LastIndex(pathString, "/")+1:]

		var keyName string
		if _, err := strconv.Atoi(final); err == nil {
			keyName = preFinal
		} else {
			keyName = pathString
		}

		if _, ok := sameNames[keyName]; ok {
			return nil
		}

		if !o.Match(part, pathString, data.(string)) {
			return nil
		}

		for _, value := range o.Append {
			builder.Reset()
			builder.WriteString(data.(string))
			builder.WriteString(value)

			transforms = append(transforms, &Transform{
				Part:  part,
				Key:   pathString,
				Value: builder.String(),
			})
		}
		for _, value := range o.Replace {
			builder.Reset()
			builder.WriteString(value)

			transforms = append(transforms, &Transform{
				Part:  part,
				Key:   pathString,
				Value: builder.String(),
			})
		}
		sameNames[keyName] = struct{}{}
		return nil
	})
	return transforms
}

// transformMapStringSlice reduces a map[string][]string to a set of transformations
func (o *AnalyzerOptions) transformMapStringSlice(part string, data map[string][]string, transforms []*Transform) []*Transform {
	builder := &strings.Builder{}

	for k, v := range data {
		var actual string
		if len(v) == 0 {
			actual = ""
		} else {
			actual = v[0]
		}

		if !o.Match(part, k, actual) {
			continue
		}

		for _, value := range o.Append {
			builder.Reset()
			builder.WriteString(actual)
			builder.WriteString(value)

			transforms = append(transforms, &Transform{
				Part:  part,
				Key:   k,
				Value: builder.String(),
			})
		}
		for _, value := range o.Replace {
			builder.Reset()
			builder.WriteString(value)

			transforms = append(transforms, &Transform{
				Part:  part,
				Key:   k,
				Value: builder.String(),
			})
		}
	}
	return transforms
}
