package dataformat

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/graphql-go/graphql/language/kinds"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/printer"
	"github.com/graphql-go/graphql/language/source"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"

	"github.com/graphql-go/graphql/language/ast"
)

type Graphql struct {
}

var (
	_ DataFormat = &Graphql{}
)

// NewGraphql returns a new GraphQL encoder
func NewGraphql() *Graphql {
	return &Graphql{}
}

// IsType returns true if the data is Graqhql encoded
func (m *Graphql) IsType(data string) bool {
	_, isGraphql, _ := isGraphQLOperation([]byte(data))
	return isGraphql
}

// consider it container type of our graphql representation
type graphQLRequest struct {
	Query         string                 `json:"query,omitempty"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

func isGraphQLOperation(jsonData []byte) (graphQLRequest, bool, error) {
	jsonStr := string(jsonData)
	if !strings.HasPrefix(jsonStr, "{") && !strings.HasSuffix(jsonStr, "}") {
		return graphQLRequest{}, false, nil
	}

	var request graphQLRequest
	if err := json.Unmarshal(jsonData, &request); err != nil {
		return graphQLRequest{}, false, nil
	}

	if request.Query == "" && request.OperationName == "" && len(request.Variables) == 0 {
		return graphQLRequest{}, false, nil
	}
	return request, true, nil
}

// Encode encodes the data into MultiPartForm format
func (m *Graphql) Encode(data KV) (string, error) {
	parsedRequest := data.Get("#_parsedReq")
	if parsedRequest == nil {
		return "", fmt.Errorf("parsed request not found")
	}
	parsedRequestStruct, ok := parsedRequest.(graphQLRequest)
	if !ok {
		return "", fmt.Errorf("parsed request is not of type graphQLRequest")
	}

	_, astDoc, err := m.parseGraphQLRequest(parsedRequestStruct.Query, false)
	if err != nil {
		return "", fmt.Errorf("error parsing graphql request: %v", err)
	}

	var hasVariables bool
	if hasVariablesItem := data.Get("#_hasVariables"); hasVariablesItem != nil {
		hasVariables, _ = hasVariablesItem.(bool)
	}

	data.Iterate(func(key string, value any) bool {
		if strings.HasPrefix(key, "#_") {
			return true
		}

		if hasVariables {
			parsedRequestStruct.Variables[key] = value
			return true
		}
		if err := m.modifyASTWithKeyValue(astDoc, key, value); err != nil {
			log.Printf("error modifying ast with key value: %v", err)
			return false
		}
		return true
	})

	modifiedQuery := printer.Print(astDoc)
	parsedRequestStruct.Query = types.ToString(modifiedQuery)

	marshalled, err := jsoniter.Marshal(parsedRequestStruct)
	if err != nil {
		return "", fmt.Errorf("error marshalling parsed request: %v", err)
	}
	return string(marshalled), nil
}

func (m *Graphql) modifyASTWithKeyValue(astDoc *ast.Document, key string, value any) error {
	for _, def := range astDoc.Definitions {
		switch v := def.(type) {
		case *ast.OperationDefinition:
			if v.SelectionSet == nil {
				continue
			}

			for _, selection := range v.SelectionSet.Selections {
				switch field := selection.(type) {
				case *ast.Field:
					for _, arg := range field.Arguments {
						if arg.Name.Value == key {
							arg.Value = convertGoValueToASTValue(value)
						}
					}
				}
			}
		}
	}
	return nil
}

// Decode decodes the data from Graphql format
func (m *Graphql) Decode(data string) (KV, error) {
	parsedReq, astDoc, err := m.parseGraphQLRequest(data, true)
	if err != nil {
		return KV{}, fmt.Errorf("error parsing graphql request: %v", err)
	}

	kv := KVMap(map[string]interface{}{})
	kv.Set("#_parsedReq", parsedReq)

	for k, v := range parsedReq.Variables {
		kv.Set(k, v)
	}
	if len(kv.Map) > 0 {
		kv.Set("#_hasVariables", true)
	}
	if err := m.populateGraphQLKV(astDoc, kv); err != nil {
		return KV{}, fmt.Errorf("error populating graphql kv: %v", err)
	}
	return kv, nil
}

func (m *Graphql) populateGraphQLKV(astDoc *ast.Document, kv KV) error {
	for _, def := range astDoc.Definitions {
		switch def := def.(type) {
		case *ast.OperationDefinition:
			args, err := getSelectionSetArguments(def)
			if err != nil {
				return fmt.Errorf("error getting selection set arguments: %v", err)
			}

			for k, v := range args {
				if item := kv.Get(k); item != nil {
					continue
				}
				kv.Set(k, v)
			}
		}
	}
	return nil
}

func (m *Graphql) parseGraphQLRequest(query string, unmarshal bool) (graphQLRequest, *ast.Document, error) {
	var parsedReq graphQLRequest
	var err error

	if unmarshal {
		parsedReq, _, err = isGraphQLOperation([]byte(query))
		if err != nil {
			return graphQLRequest{}, nil, fmt.Errorf("error parsing query: %v", err)
		}
	} else {
		parsedReq.Query = query
	}

	astDoc, err := parser.Parse(parser.ParseParams{
		Source: &source.Source{
			Body: []byte(parsedReq.Query),
		},
	})
	if err != nil {
		return graphQLRequest{}, nil, fmt.Errorf("error parsing query: %v", err)
	}
	return parsedReq, astDoc, nil
}

func getSelectionSetArguments(def *ast.OperationDefinition) (map[string]interface{}, error) {
	args := make(map[string]interface{})

	if def.SelectionSet == nil {
		return args, nil
	}
	for _, selection := range def.SelectionSet.Selections {
		switch field := selection.(type) {
		case *ast.Field:
			for _, arg := range field.Arguments {
				args[arg.Name.Value] = convertValueToGoType(arg.Value)
			}
		}
	}
	return args, nil
}

func convertGoValueToASTValue(value any) ast.Value {
	switch v := value.(type) {
	case string:
		newValue := &ast.StringValue{
			Kind:  kinds.StringValue,
			Value: v,
		}
		return newValue
	}
	return nil
}

func convertValueToGoType(value ast.Value) interface{} {
	switch value := value.(type) {
	case *ast.StringValue:
		return value.Value
	case *ast.IntValue:
		return value.Value
	case *ast.FloatValue:
		return value.Value
	case *ast.BooleanValue:
		return value.Value
	case *ast.EnumValue:
		return value.Value
	case *ast.ListValue:
		var list []interface{}
		for _, v := range value.Values {
			list = append(list, convertValueToGoType(v))
		}
		return list
	case *ast.ObjectValue:
		obj := make(map[string]interface{})
		for _, v := range value.Fields {
			obj[v.Name.Value] = convertValueToGoType(v.Value)
		}
		return obj
	}

	return nil

}

// Name returns the name of the encoder
func (m *Graphql) Name() string {
	return "graphql"
}
