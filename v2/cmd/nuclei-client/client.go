package main

import (
	"bytes"
	"log"
	"os"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
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
		&cli.StringFlag{Name: "username", Usage: "Username of the Nuclei Server", Value: "user"},
		&cli.StringFlag{Name: "password", Usage: "Password of the Nuclei Server", Value: "pass"},
	}
	// Initialize nuclei client before being used
	app.Before = cli.BeforeFunc(func(ctx *cli.Context) error {
		noColor = ctx.Bool("no-color")

		var opts []client.Option
		if url := ctx.String("url"); url != "" {
			opts = append(opts, client.WithBaseURL(url))
		}
		username := ctx.String("username")
		password := ctx.String("password")

		if username != "" && password != "" {
			opts = append(opts, client.WithBasicAuth(username, password))
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
