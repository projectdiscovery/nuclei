package workflows

import (
	"log"

	"github.com/d5/tengo/v2"
	"github.com/projectdiscovery/nuclei/pkg/executor"
)

type NucleiVar struct {
	tengo.ObjectImpl
	Options *executor.HTTPOptions
	URL     string
}

func (n *NucleiVar) TypeName() string {
	return "nuclei-var"
}

func (n *NucleiVar) CanCall() bool {
	return true
}

func (n *NucleiVar) Call(args ...tengo.Object) (ret tengo.Object, err error) {
	for _, request := range n.Options.Template.RequestsHTTP {
		n.Options.HTTPRequest = request
		httpExecutor, err := executor.NewHTTPExecutor(n.Options)
		if err != nil {
			log.Fatal(err)
		}
		err = httpExecutor.ExecuteHTTP(n.URL)
		if err != nil {
			log.Fatal(err)
		}
		if httpExecutor.GotResults() {
			return tengo.TrueValue, nil
		}
		return tengo.FalseValue, nil
	}

	return nil, nil
}
