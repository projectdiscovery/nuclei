package extractors

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
)

type SupportedExtractorTypes []ExtractorType

func (extractTypes *SupportedExtractorTypes) Set(values string) error {
	inputTypes, err := goflags.ToNormalizedStringSlice(values)
	if err != nil {
		return err
	}

	for _, inputType := range inputTypes {
		if err := setExtractType(extractTypes, inputType); err != nil {
			return err
		}
	}
	return nil
}

func (extractTypes *SupportedExtractorTypes) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var stringSliceValue stringslice.StringSlice
	if err := unmarshal(&stringSliceValue); err != nil {
		return err
	}

	stringSLice := stringSliceValue.ToSlice()
	var result = make(SupportedExtractorTypes, 0, len(stringSLice))
	for _, typeString := range stringSLice {
		if err := setExtractType(&result, typeString); err != nil {
			return err
		}
	}
	*extractTypes = result
	return nil
}

func (extractTypes SupportedExtractorTypes) String() string {
	var stringTypes []string
	for _, t := range extractTypes {
		stringTypes = append(stringTypes, t.String())
	}
	return strings.Join(stringTypes, ", ")
}

func setExtractType(extractTypes *SupportedExtractorTypes, value string) error {
	computedType, err := toExtractorTypes(value)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid extract type", value)
	}
	*extractTypes = append(*extractTypes, computedType)
	return nil
}
