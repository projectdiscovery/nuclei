package variables

// Scope contains values used while evaluating template variables.
//
// Data values are terminal values from runtime, options, constants, payloads,
// or protocol context. Template values are produced from the template variables
// section and may be re-rendered when later data becomes available.
type Scope struct {
	values map[string]scopeValue
}

type scopeValueKind uint8

const (
	scopeValueData scopeValueKind = iota
	scopeValueTemplate
)

type scopeValue struct {
	value interface{}
	kind  scopeValueKind
}

// NewScope creates an empty variable evaluation scope.
func NewScope() *Scope {
	return &Scope{values: make(map[string]scopeValue)}
}

// AddData adds terminal data values to the scope.
func (s *Scope) AddData(values ...map[string]interface{}) *Scope {
	if s == nil {
		return s
	}

	for _, valueMap := range values {
		for key, value := range valueMap {
			s.AddDataValue(key, value)
		}
	}

	return s
}

// AddDataValue adds one terminal data value to the scope.
func (s *Scope) AddDataValue(key string, value interface{}) *Scope {
	if s == nil {
		return s
	}

	s.values[key] = scopeValue{value: value, kind: scopeValueData}

	return s
}

// AddTemplate adds values produced from template variables.
func (s *Scope) AddTemplate(values map[string]interface{}) *Scope {
	if s == nil {
		return s
	}

	for key, value := range values {
		s.AddTemplateValue(key, value)
	}

	return s
}

// AddTemplateValue adds one value produced from template variables.
func (s *Scope) AddTemplateValue(key string, value interface{}) *Scope {
	if s == nil {
		return s
	}

	s.values[key] = scopeValue{value: value, kind: scopeValueTemplate}

	return s
}

// Values returns a plain value map for render evaluation.
func (s *Scope) Values() map[string]interface{} {
	if s == nil || len(s.values) == 0 {
		return nil
	}

	values := make(map[string]interface{}, len(s.values))
	for key, value := range s.values {
		values[key] = value.value
	}

	return values
}

func (s *Scope) clone() *Scope {
	if s == nil {
		return NewScope()
	}

	clone := NewScope()
	for key, value := range s.values {
		clone.values[key] = value
	}

	return clone
}

func (s *Scope) get(key string) (scopeValue, bool) {
	if s == nil {
		return scopeValue{}, false
	}

	value, ok := s.values[key]

	return value, ok
}
