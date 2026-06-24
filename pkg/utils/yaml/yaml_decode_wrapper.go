package yaml

import (
	"bytes"
	"io"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

var validate *validator.Validate

// Marshaler is the YAML marshaling interface used by the project.
type Marshaler interface {
	MarshalYAML() (interface{}, error)
}

// Unmarshaler is the legacy callback-style YAML unmarshaling interface used
// throughout nuclei. yaml.v3 still supports this shape, but does not export it.
type Unmarshaler interface {
	UnmarshalYAML(unmarshal func(interface{}) error) error
}

// TypeError is returned for YAML type conversion errors.
type TypeError = yaml.TypeError

// Node is the yaml.v3 syntax tree node type.
type Node = yaml.Node

// MapItem is a single YAML mapping item.
type MapItem struct {
	Key   interface{}
	Value interface{}
}

// MapSlice preserves mapping key order for compatibility with yaml.v2.
type MapSlice []MapItem

// Encoder writes YAML documents.
type Encoder = yaml.Encoder

// Marshal serializes a value to YAML.
func Marshal(v interface{}) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Unmarshal deserializes YAML using yaml.v2-compatible lax duplicate-key
// behavior. In lax mode yaml.v2 allowed duplicate mapping keys and kept the
// last value; yaml.v3 rejects duplicates by default, so normalize first.
func Unmarshal(data []byte, v interface{}) error {
	return NewDecoder(bytes.NewReader(data)).Decode(v)
}

// UnmarshalStrict deserializes YAML and rejects unknown struct fields and
// duplicate mapping keys.
func UnmarshalStrict(data []byte, v interface{}) error {
	decoder := NewDecoder(bytes.NewReader(data))
	decoder.SetStrict(true)
	return decoder.Decode(v)
}

// NewEncoder returns a YAML encoder.
func NewEncoder(w io.Writer) *Encoder {
	return yaml.NewEncoder(w)
}

// Decoder reads YAML documents.
type Decoder struct {
	decoder *yaml.Decoder
	strict  bool
}

// NewDecoder returns a YAML decoder.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{decoder: yaml.NewDecoder(r)}
}

// SetStrict matches yaml.v2's decoder API.
func (d *Decoder) SetStrict(strict bool) {
	d.strict = strict
	d.decoder.KnownFields(strict)
}

// KnownFields matches yaml.v3's decoder API.
func (d *Decoder) KnownFields(enable bool) {
	d.SetStrict(enable)
}

// Decode reads the next YAML document into v.
func (d *Decoder) Decode(v interface{}) error {
	if d.strict {
		if err := d.decoder.Decode(v); err != nil {
			return err
		}
		restoreYAMLv2InterfaceMapShape(v)
		return nil
	}

	var node yaml.Node
	if err := d.decoder.Decode(&node); err != nil {
		return err
	}
	normalizeDupMappingKeys(&node)
	if err := node.Decode(v); err != nil {
		return err
	}
	restoreYAMLv2InterfaceMapShape(v)
	return nil
}

// UnmarshalYAML decodes an ordered map from a yaml.v3 node.
func (m *MapSlice) UnmarshalYAML(node *Node) error {
	node = unwrapDoc(node)
	if node == nil || node.Kind == 0 {
		*m = nil
		return nil
	}
	if node.Kind != yaml.MappingNode {
		var value interface{}
		if err := node.Decode(&value); err != nil {
			return err
		}
		return errors.Errorf("cannot unmarshal %T into yaml.MapSlice", value)
	}

	items := make([]MapItem, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		var item MapItem
		if err := node.Content[i].Decode(&item.Key); err != nil {
			return err
		}
		if err := node.Content[i+1].Decode(&item.Value); err != nil {
			return err
		}
		item.Value = toYAMLv2InterfaceValue(item.Value)
		items = append(items, item)
	}
	*m = items
	return nil
}

// DecodeAndValidate is a wrapper for yaml Decode adding struct validation
func DecodeAndValidate(r io.Reader, v interface{}) error {
	if err := NewDecoder(r).Decode(v); err != nil {
		return err
	}
	if validate == nil {
		validate = validator.New()
	}

	if err := validate.Struct(v); err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return err
		}
		errs := []string{}
		for _, err := range err.(validator.ValidationErrors) {
			errs = append(errs, err.Namespace()+": "+err.Tag())
		}
		return errors.Wrap(errors.New(strings.Join(errs, ", ")), "validation failed for these fields")
	}
	return nil
}

func normalizeDupMappingKeys(node *yaml.Node) {
	node = unwrapDoc(node)
	if node == nil {
		return
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			normalizeDupMappingKeys(child)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			normalizeDupMappingKeys(child)
		}
	case yaml.MappingNode:
		type pair struct {
			key   *yaml.Node
			value *yaml.Node
		}
		pairs := make([]pair, 0, len(node.Content)/2)
		indexes := make(map[string]int, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			normalizeDupMappingKeys(value)

			identity := mappingKeyIdentity(key)
			if existing, ok := indexes[identity]; ok {
				pairs[existing].value = value
				continue
			}
			indexes[identity] = len(pairs)
			pairs = append(pairs, pair{key: key, value: value})
		}

		node.Content = node.Content[:0]
		for _, item := range pairs {
			node.Content = append(node.Content, item.key, item.value)
		}
	}
}

func mappingKeyIdentity(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	return string(rune(node.Kind)) + "\x00" + node.Value
}

func unwrapDoc(node *yaml.Node) *yaml.Node {
	if node != nil && node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return node.Content[0]
	}
	return node
}

func restoreYAMLv2InterfaceMapShape(v interface{}) {
	value := reflect.ValueOf(v)
	if !value.IsValid() {
		return
	}
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return
	}
	restoreYAMLv2InterfaceMapShapeValue(value.Elem())
}

func restoreYAMLv2InterfaceMapShapeValue(value reflect.Value) {
	if !value.IsValid() {
		return
	}

	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() || !value.CanSet() {
			return
		}
		setInterfaceValue(value, toYAMLv2InterfaceValue(value.Interface()))
	case reflect.Pointer:
		if !value.IsNil() {
			restoreYAMLv2InterfaceMapShapeValue(value.Elem())
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			if field.CanSet() {
				restoreYAMLv2InterfaceMapShapeValue(field)
			}
		}
	case reflect.Map:
		if value.Type().Elem().Kind() != reflect.Interface {
			return
		}
		for _, key := range value.MapKeys() {
			normalized := toYAMLv2InterfaceValue(value.MapIndex(key).Interface())
			value.SetMapIndex(key, interfaceValueForMap(value.Type().Elem(), normalized))
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			restoreYAMLv2InterfaceMapShapeValue(value.Index(i))
		}
	}
}

func toYAMLv2InterfaceValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		converted := make(map[interface{}]interface{}, len(typed))
		for key, item := range typed {
			converted[key] = toYAMLv2InterfaceValue(item)
		}
		return converted
	case []interface{}:
		for i, item := range typed {
			typed[i] = toYAMLv2InterfaceValue(item)
		}
		return typed
	default:
		return value
	}
}

func setInterfaceValue(dst reflect.Value, value interface{}) {
	if value == nil {
		dst.Set(reflect.Zero(dst.Type()))
		return
	}
	dst.Set(reflect.ValueOf(value))
}

func interfaceValueForMap(elem reflect.Type, value interface{}) reflect.Value {
	if value == nil {
		return reflect.Zero(elem)
	}
	return reflect.ValueOf(value)
}
