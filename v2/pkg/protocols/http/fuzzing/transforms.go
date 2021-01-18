package fuzzing

import (
	"strings"
)

// Transform contains the ways described to transform  a document a single
// time. Each transformation will be done one by one leading to fuzzing
// of all request parts in a synchronous manner.
type Transform struct {
	Part  string
	Key   string
	Value string
}

/*
Path string
MultipartBody map[string]NormalizedMultipartField
FormData map[string][]string
JSONData map[string]interface{}
XMLData map[string]interface{}
Body string
QueryValues map[string][]string
Headers http.Header
Cookies map[string]string
*/

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
	}

	builder := &strings.Builder{}
	builder.Grow(len(req.Path))

	matched := options.Match("path", req.Path, "")
	if _, ok := parts["path"]; ok && matched {
		for _, v := range options.Append {
			builder.Reset()
			builder.WriteString(req.Path)
			if !strings.HasSuffix(req.Path, "/") {
				builder.WriteString("/")
			}
			builder.WriteString(v)

			transforms = append(transforms, &Transform{
				Part:  "path",
				Value: builder.String(),
			})
		}
		for _, v := range options.Replace {
			builder.Reset()
			builder.WriteString(req.Path[:strings.LastIndex(req.Path, "/")+1])
			builder.WriteString(v)

			transforms = append(transforms, &Transform{
				Part:  "path",
				Value: builder.String(),
			})
		}
	}

	if _, ok := parts["query-values"]; ok {
		for k, v := range req.QueryValues {
			if len(v) == 0 {
				continue
			}
			if !options.Match("query-values", k, v[0]) {
				continue
			}

			for _, value := range options.Append {
				builder.Reset()
				builder.WriteString(v[0])
				builder.WriteString(value)

				transforms = append(transforms, &Transform{
					Part:  "query-values",
					Key:   k,
					Value: builder.String(),
				})
			}
			for _, value := range options.Replace {
				builder.Reset()
				builder.WriteString(value)

				transforms = append(transforms, &Transform{
					Part:  "query-values",
					Key:   k,
					Value: builder.String(),
				})
			}
		}
	}

	if _, ok := parts["headers"]; ok {
		for k, v := range req.Headers {
			if len(v) == 0 {
				continue
			}
			if !options.Match("headers", k, v[0]) {
				continue
			}

			for _, value := range options.Append {
				builder.Reset()
				builder.WriteString(v[0])
				builder.WriteString(value)

				transforms = append(transforms, &Transform{
					Part:  "headers",
					Key:   k,
					Value: builder.String(),
				})
			}
			for _, value := range options.Replace {
				builder.Reset()
				builder.WriteString(value)

				transforms = append(transforms, &Transform{
					Part:  "headers",
					Key:   k,
					Value: builder.String(),
				})
			}
		}
	}

	if _, ok := parts["cookies"]; ok {
		for k, v := range req.Cookies {
			if !options.Match("cookies", k, v) {
				continue
			}

			for _, value := range options.Append {
				builder.Reset()
				builder.WriteString(v)
				builder.WriteString(value)

				transforms = append(transforms, &Transform{
					Part:  "cookies",
					Key:   k,
					Value: builder.String(),
				})
			}
			for _, value := range options.Replace {
				builder.Reset()
				builder.WriteString(value)

				transforms = append(transforms, &Transform{
					Part:  "cookies",
					Key:   k,
					Value: builder.String(),
				})
			}
		}
	}
	return transforms
}
