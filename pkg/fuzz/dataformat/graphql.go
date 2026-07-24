package dataformat

import (
	"fmt"
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
	Query         string         `json:"query,omitempty"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
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

	hasVariables := len(body.Variables) > 0
	if hasVariables {
		kv.Set(graphqlMetaHasVariables, true)
		for key, value := range body.Variables {
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

	body := graphQLHTTPBody{
		Query:     query,
		Variables: map[string]any{},
	}
	if op := data.Get(graphqlMetaOperationName); op != nil {
		body.OperationName = types.ToString(op)
	}

	hasVariables, _ := data.Get(graphqlMetaHasVariables).(bool)
	if hasVariables {
		data.Iterate(func(key string, value any) bool {
			if strings.HasPrefix(key, "#_") {
				return true
			}
			body.Variables[key] = value
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
	walkFields(doc, func(field *ast.Field) {
		for _, arg := range field.Arguments {
			if arg.Name == nil {
				continue
			}
			args[arg.Name.Value] = astValueToGo(arg.Value)
		}
	})
	return args
}

func applyInlineArgument(doc *ast.Document, key string, value any) {
	walkFields(doc, func(field *ast.Field) {
		for _, arg := range field.Arguments {
			if arg.Name != nil && arg.Name.Value == key {
				arg.Value = goValueToAST(value)
			}
		}
	})
}

func walkFields(doc *ast.Document, fn func(*ast.Field)) {
	if doc == nil {
		return
	}
	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok || op.SelectionSet == nil {
			continue
		}
		walkSelectionSet(op.SelectionSet, fn)
	}
}

func walkSelectionSet(set *ast.SelectionSet, fn func(*ast.Field)) {
	if set == nil {
		return
	}
	for _, selection := range set.Selections {
		field, ok := selection.(*ast.Field)
		if !ok {
			continue
		}
		fn(field)
		walkSelectionSet(field.SelectionSet, fn)
	}
}

func goValueToAST(value any) ast.Value {
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
