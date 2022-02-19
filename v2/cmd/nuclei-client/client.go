package main

import (
	"bytes"
	"log"
	"os"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/client"
	"github.com/tidwall/pretty"
	"github.com/urfave/cli/v2"
)

var nucleiClient *client.Client

var noColor bool

// renderJSON renders an item to the stdout
func renderJSON(item interface{}) error {
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(item)

	var got []byte
	if noColor {
		got = pretty.Pretty(buf.Bytes())
	} else {
		got = pretty.Color(pretty.Pretty(buf.Bytes()), nil)
	}
	os.Stdout.Write(got)
	return nil
}

func main() {
	app := cli.NewApp()
	app.Usage = "Nuclei REST API Client"
	app.Flags = []cli.Flag{
		&cli.BoolFlag{Name: "no-color", Aliases: []string{"nc"}, Usage: "Do not print colors"},
		&cli.StringFlag{Name: "url", Usage: "Base URL of the Nuclei Server"},
		&cli.StringFlag{Name: "token", Usage: "Token for the Nuclei Server"},
	}
	// Initialize nuclei client before being used
	app.Before = cli.BeforeFunc(func(ctx *cli.Context) error {
		noColor = ctx.Bool("no-color")

		if server := os.Getenv("NUCLEI_API_SERVER"); server != "" && !ctx.IsSet("url") {
			ctx.Set("url", server)
		}
		if token := os.Getenv("NUCLEI_API_TOKEN"); token != "" && !ctx.IsSet("token") {
			ctx.Set("token", token)
		}
		var opts []client.Option
		if url := ctx.String("url"); url != "" {
			opts = append(opts, client.WithBaseURL(url))
		}
		token := ctx.String("token")

		if token != "" {
			opts = append(opts, client.WithToken(token))
		}
		nucleiClient = client.New(opts...)
		return nil
	})
	app.EnableBashCompletion = true
	app.Commands = []*cli.Command{
		issues,
		scans,
		targets,
		settings,
		templates,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
