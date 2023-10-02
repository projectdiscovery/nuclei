package postman

import (
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	postman "github.com/rbretecher/go-postman-collection"
)

// PostmanFormat is a Postman Collection File parser
type PostmanFormat struct{}

// New creates a new Postman format parser
func New() *PostmanFormat {
	return &PostmanFormat{}
}

var _ formats.Format = &PostmanFormat{}

// Name returns the name of the format
func (j *PostmanFormat) Name() string {
	return "postman"
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *PostmanFormat) Parse(input string, resultsCb formats.RawRequestCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open data file")
	}
	defer file.Close()

	c, err := postman.ParseCollection(file)
	if err != nil {
		return errors.Wrap(err, "could not decode postman schema")
	}

	// TODO: Support postman variables and more auth types + collection
	// level variables and items.
	for _, v := range c.Items {
		request := v.Request

		req, err := http.NewRequest(string(request.Method), request.URL.String(), strings.NewReader(request.Body.Raw))
		if err != nil {
			continue
		}
		for _, header := range request.Header {
			req.Header.Set(header.Key, header.Value)
		}

		if request.Auth != nil {
			params := request.Auth.GetParams()
			authMap := make(map[string]string)
			for _, item := range params {
				authMap[item.Key] = types.ToString(item.Value)
			}

			switch request.Auth.Type {
			case "apikey":
				in := authMap["in"]
				if in == "header" {
					req.Header.Set(authMap["key"], authMap["value"])
				}
			case "basic":
				req.SetBasicAuth(authMap["username"], authMap["password"])
			case "bearer":
				req.Header.Set("Authorization", "Bearer "+authMap["token"])
			case "noauth":
			default:
				gologger.Error().Msgf("could not parse requeest auth")
			}
		}

		dumped, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			return errors.Wrap(err, "could not dump request")
		}
		resultsCb(&formats.RawRequest{
			Method:  string(request.Method),
			URL:     request.URL.String(),
			Headers: req.Header,
			Body:    request.Body.Raw,
			Raw:     string(dumped),
		})
	}
	return nil
}
