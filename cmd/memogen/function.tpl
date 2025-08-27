// Warning - This is generated code
package {{.SourcePackage}}

import (
    "github.com/projectdiscovery/utils/memoize"
    
    {{range .Imports}}
        {{.Name}} {{.Path}}
    {{end}}    
)

{{range .Functions}}
    {{ .SignatureWithPrefix "memoized" }} {
        hash := "{{ .Name }}" {{range .Params}} + ":" + fmt.Sprint({{.Name}}) {{end}}

        v, err, _ := protocolstate.Memoizer.Do(hash, func() (interface{}, error) {
            return {{.Name}}({{.ParamsNames}})
        })
        if err != nil {
            return {{.ResultFirstFieldDefaultValue}}, err
        }
        if value, ok := v.({{.ResultFirstFieldType}}); ok {
            return value, nil
        }

        return {{.ResultFirstFieldDefaultValue}}, errors.New("could not convert cached result")
    }
{{end}}  