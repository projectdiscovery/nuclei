package dataformat

import (
	"fmt"
	"sort"
	"strings"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/kinds"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/printer"
	"github.com/graphql-go/graphql/language/source"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

const (
	graphqlMetaQuery         = "#_query"
	graphqlMetaOperationName = "#_operationName"
	graphqlMetaHasVariables  = "#_hasVariables"
)

// Graphql encodes and decodes GraphQL-over-HTTP JSON bodies
// ({"query","variables","operationName"}) so DAST fuzzing can target
// variables and inline field arguments instead of the raw query string.
type Graphql struct{}

var _ DataFormat = &Graphql{}

// NewGraphql returns a new GraphQL data format encoder/decoder.
func NewGraphql() *Graphql {
	return &Graphql{}
}

// Name returns the name of the data format.
func (g *Graphql) Name() string {
	return GraphqlDataFormat
}

// IsType reports whether data is a GraphQL HTTP request body.
func (g *Graphql) IsType(data string) bool {
	_, ok := parseGraphQLHTTPBody(data, true)
	return ok
}

type graphQLHTTPBody struct {
	Query         string          `json:"query,omitempty"`
	OperationName string          `json:"operationName,omitempty"`
	Variables     *map[string]any `json:"variables,omitempty"`
}

func parseGraphQLHTTPBody(data string, validateQuery bool) (graphQLHTTPBody, bool) {
	trimmed := strings.TrimSpace(data)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return graphQLHTTPBody{}, false
	}

	var body graphQLHTTPBody
	if err := json.Unmarshal([]byte(trimmed), &body); err != nil {
		return graphQLHTTPBody{}, false
	}
	if strings.TrimSpace(body.Query) == "" {
		return graphQLHTTPBody{}, false
	}
	if !validateQuery {
		return body, true
	}
	if _, err := parseQueryAST(body.Query); err != nil {
		return graphQLHTTPBody{}, false
	}
	return body, true
}

func parseQueryAST(query string) (*ast.Document, error) {
	return parser.Parse(parser.ParseParams{
		Source: &source.Source{Body: []byte(query)},
	})
}

// Decode extracts fuzzable GraphQL variables / inline arguments.
func (g *Graphql) Decode(data string) (KV, error) {
	body, ok := parseGraphQLHTTPBody(data, true)
	if !ok {
		return KV{}, fmt.Errorf("not a graphql http body")
	}
	doc, err := parseQueryAST(body.Query)
	if err != nil {
		return KV{}, fmt.Errorf("could not parse graphql query: %w", err)
	}

	kv := KVMap(map[string]any{})
	kv.Set(graphqlMetaQuery, body.Query)
	if body.OperationName != "" {
		kv.Set(graphqlMetaOperationName, body.OperationName)
	}

	hasVariables := body.Variables != nil
	if hasVariables {
		kv.Set(graphqlMetaHasVariables, true)
		for key, value := range *body.Variables {
			kv.Set(key, value)
		}
	}

	// Inline arguments are only exposed when variables are absent; otherwise
	// variables are the stable fuzz surface (and rewrites stay in JSON).
	if !hasVariables {
		for key, value := range collectInlineArguments(doc) {
			if kv.Get(key) != nil {
				continue
			}
			kv.Set(key, value)
		}
	}
	return kv, nil
}

// Encode rebuilds a GraphQL HTTP JSON body from fuzzed KV values.
func (g *Graphql) Encode(data KV) (string, error) {
	queryVal := data.Get(graphqlMetaQuery)
	if queryVal == nil {
		return "", fmt.Errorf("graphql query metadata missing")
	}
	query := types.ToString(queryVal)

	body := graphQLHTTPBody{Query: query}
	if op := data.Get(graphqlMetaOperationName); op != nil {
		body.OperationName = types.ToString(op)
	}

	hasVariables, _ := data.Get(graphqlMetaHasVariables).(bool)
	if hasVariables {
		variables := make(map[string]any)
		body.Variables = &variables
		data.Iterate(func(key string, value any) bool {
			if strings.HasPrefix(key, "#_") {
				return true
			}
			variables[key] = value
			return true
		})
	} else {
		doc, err := parseQueryAST(query)
		if err != nil {
			return "", fmt.Errorf("could not parse graphql query: %w", err)
		}
		data.Iterate(func(key string, value any) bool {
			if strings.HasPrefix(key, "#_") {
				return true
			}
			applyInlineArgument(doc, key, value)
			return true
		})
		body.Query = types.ToString(printer.Print(doc))
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func collectInlineArguments(doc *ast.Document) map[string]any {
	args := make(map[string]any)
	for _, ref := range inlineArgumentRefs(doc) {
		args[ref.key] = astValueToGo(ref.argument.Value)
	}
	return args
}

func applyInlineArgument(doc *ast.Document, key string, value any) {
	for _, ref := range inlineArgumentRefs(doc) {
		if ref.key == key {
			ref.argument.Value = goValueToAST(value, ref.argument.Value)
			return
		}
	}
}

type inlineArgumentRef struct {
	key      string
	path     string
	argument *ast.Argument
}

func inlineArgumentRefs(doc *ast.Document) []inlineArgumentRef {
	var refs []inlineArgumentRef
	walkFields(doc, func(path string, field *ast.Field) {
		for _, argument := range field.Arguments {
			if argument.Name == nil {
				continue
			}
			refs = append(refs, inlineArgumentRef{
				path:     path,
				argument: argument,
			})
		}
	})

	counts := make(map[string]int)
	for _, ref := range refs {
		counts[ref.argument.Name.Value]++
	}
	for index := range refs {
		name := refs[index].argument.Name.Value
		refs[index].key = name
		if counts[name] > 1 {
			refs[index].key = refs[index].path + "." + name
		}
	}

	keyCounts := make(map[string]int)
	for _, ref := range refs {
		keyCounts[ref.key]++
	}
	keyIndexes := make(map[string]int)
	for index := range refs {
		key := refs[index].key
		keyIndexes[key]++
		if keyCounts[key] > 1 {
			refs[index].key = fmt.Sprintf("%s[%d]", key, keyIndexes[key])
		}
	}
	return refs
}

func walkFields(doc *ast.Document, fn func(string, *ast.Field)) {
	if doc == nil {
		return
	}
	for _, def := range doc.Definitions {
		switch typed := def.(type) {
		case *ast.OperationDefinition:
			prefix := ""
			if typed.Name != nil {
				prefix = typed.Name.Value
			}
			walkSelectionSet(typed.SelectionSet, prefix, fn)
		case *ast.FragmentDefinition:
			prefix := "fragment"
			if typed.Name != nil {
				prefix += "." + typed.Name.Value
			}
			walkSelectionSet(typed.SelectionSet, prefix, fn)
		}
	}
}

func walkSelectionSet(set *ast.SelectionSet, parentPath string, fn func(string, *ast.Field)) {
	if set == nil {
		return
	}

	fieldCounts := make(map[string]int)
	for _, selection := range set.Selections {
		if field, ok := selection.(*ast.Field); ok {
			fieldCounts[fieldResponseName(field)]++
		}
	}
	fieldIndexes := make(map[string]int)

	for _, selection := range set.Selections {
		switch typed := selection.(type) {
		case *ast.Field:
			name := fieldResponseName(typed)
			fieldIndexes[name]++
			if fieldCounts[name] > 1 {
				name = fmt.Sprintf("%s[%d]", name, fieldIndexes[name])
			}
			path := name
			if parentPath != "" {
				path = parentPath + "." + name
			}
			fn(path, typed)
			walkSelectionSet(typed.SelectionSet, path, fn)
		case *ast.InlineFragment:
			walkSelectionSet(typed.SelectionSet, parentPath, fn)
		}
	}
}

func fieldResponseName(field *ast.Field) string {
	if field.Alias != nil {
		return field.Alias.Value
	}
	if field.Name != nil {
		return field.Name.Value
	}
	return "field"
}

func goValueToAST(value any, original ast.Value) ast.Value {
	switch original.(type) {
	case *ast.IntValue:
		return &ast.IntValue{Kind: kinds.IntValue, Value: types.ToString(value)}
	case *ast.FloatValue:
		return &ast.FloatValue{Kind: kinds.FloatValue, Value: types.ToString(value)}
	case *ast.EnumValue:
		return &ast.EnumValue{Kind: kinds.EnumValue, Value: types.ToString(value)}
	case *ast.StringValue:
		return &ast.StringValue{Kind: kinds.StringValue, Value: types.ToString(value)}
	}

	switch v := value.(type) {
	case string:
		return &ast.StringValue{Kind: kinds.StringValue, Value: v}
	case bool:
		return &ast.BooleanValue{Kind: kinds.BooleanValue, Value: v}
	case int:
		return &ast.IntValue{Kind: kinds.IntValue, Value: fmt.Sprintf("%d", v)}
	case int32:
		return &ast.IntValue{Kind: kinds.IntValue, Value: fmt.Sprintf("%d", v)}
	case int64:
		return &ast.IntValue{Kind: kinds.IntValue, Value: fmt.Sprintf("%d", v)}
	case float32:
		return &ast.FloatValue{Kind: kinds.FloatValue, Value: fmt.Sprintf("%v", v)}
	case float64:
		// JSON numbers decode as float64; keep integers looking like ints when possible.
		if v == float64(int64(v)) {
			return &ast.IntValue{Kind: kinds.IntValue, Value: fmt.Sprintf("%d", int64(v))}
		}
		return &ast.FloatValue{Kind: kinds.FloatValue, Value: fmt.Sprintf("%v", v)}
	case []any:
		originalList, _ := original.(*ast.ListValue)
		values := make([]ast.Value, 0, len(v))
		for index, item := range v {
			var originalItem ast.Value
			if originalList != nil && index < len(originalList.Values) {
				originalItem = originalList.Values[index]
			}
			values = append(values, goValueToAST(item, originalItem))
		}
		return &ast.ListValue{Kind: kinds.ListValue, Values: values}
	case map[string]any:
		originalObject, _ := original.(*ast.ObjectValue)
		fields := make([]*ast.ObjectField, 0, len(v))
		used := make(map[string]struct{}, len(v))
		if originalObject != nil {
			for _, field := range originalObject.Fields {
				if field.Name == nil {
					continue
				}
				name := field.Name.Value
				value, ok := v[name]
				if !ok {
					continue
				}
				fields = append(fields, &ast.ObjectField{
					Kind:  kinds.ObjectField,
					Name:  &ast.Name{Kind: kinds.Name, Value: name},
					Value: goValueToAST(value, field.Value),
				})
				used[name] = struct{}{}
			}
		}

		names := make([]string, 0, len(v)-len(used))
		for name := range v {
			if _, ok := used[name]; !ok {
				names = append(names, name)
			}
		}
		sort.Strings(names)

		for _, name := range names {
			fields = append(fields, &ast.ObjectField{
				Kind:  kinds.ObjectField,
				Name:  &ast.Name{Kind: kinds.Name, Value: name},
				Value: goValueToAST(v[name], nil),
			})
		}
		return &ast.ObjectValue{Kind: kinds.ObjectValue, Fields: fields}
	default:
		return &ast.StringValue{Kind: kinds.StringValue, Value: types.ToString(v)}
	}
}

func astValueToGo(value ast.Value) any {
	switch v := value.(type) {
	case *ast.StringValue:
		return v.Value
	case *ast.IntValue:
		return v.Value
	case *ast.FloatValue:
		return v.Value
	case *ast.BooleanValue:
		return v.Value
	case *ast.EnumValue:
		return v.Value
	case *ast.ListValue:
		out := make([]any, 0, len(v.Values))
		for _, item := range v.Values {
			out = append(out, astValueToGo(item))
		}
		return out
	case *ast.ObjectValue:
		out := make(map[string]any, len(v.Fields))
		for _, field := range v.Fields {
			if field.Name == nil {
				continue
			}
			out[field.Name.Value] = astValueToGo(field.Value)
		}
		return out
	default:
		return nil
	}
}
