package main

import (
	"bytes"
	"log"
	"os"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
	"github.com/tidwall/pretty"
	"github.com/urfave/cli/v2"
)

var nucleiClient *client.Client

var issues = &cli.Command{
	Name:  "issues",
	Usage: "issues related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns list of issue(s)",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "search", Usage: "value to search in issues"},
				&cli.Int64Flag{Name: "id", Usage: "ID of the issue to retrieve"},
			},
			Action: func(c *cli.Context) error {
				if id := c.Int64("id"); id != 0 {
					if resp, err := nucleiClient.Issues.GetIssue(id); err != nil {
						return errors.Wrap(err, "could not get issue for id")
					} else {
						renderJSON(resp)
					}
					return nil
				}
				search := c.String("search")
				response, err := nucleiClient.Issues.GetIssues(client.GetIssuesRequest{Search: search})
				if err != nil {
					return errors.Wrap(err, "could not get issues")
				}
				renderJSON(response)
				return nil
			},
		},
		{
			Name:  "add",
			Usage: "add a new issue to list",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "update",
			Usage: "update an existing issue",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing issue",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
	Action: func(c *cli.Context) error {
		return nil
	},
}

var scans = &cli.Command{
	Name:  "scans",
	Usage: "scan related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns list of scan(s)",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "add",
			Usage: "adds a new scan to queue",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "progress",
			Usage: "returns running scan progress",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "update",
			Usage: "update an existing scan",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing scan",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "execute",
			Usage: "execute an existing scan",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "matches",
			Usage: "matches for an existing scan",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "errors",
			Usage: "errors for an existing scan",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
	Action: func(c *cli.Context) error {
		return nil
	},
}

var targets = &cli.Command{
	Name:  "targets",
	Usage: "target related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns list of targets",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "add",
			Usage: "add a new target",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "update",
			Usage: "update an existing target",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing target",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "contents",
			Usage: "contents for an existing target",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
}

var settings = &cli.Command{
	Name:  "settings",
	Usage: "setting related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns setting(s) from server",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "update",
			Usage: "updates an existing setting",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "add",
			Usage: "add a new setting to storage",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
	Action: func(c *cli.Context) error {
		return nil
	},
}

var templates = &cli.Command{
	Name:  "templates",
	Usage: "templates related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns template(s) from server",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "search", Usage: "value to search in templates"},
				&cli.StringFlag{Name: "folder", Usage: "folder to search in templates"},
			},
			Action: func(c *cli.Context) error {
				search := c.String("search")
				folder := c.String("folder")
				response, err := nucleiClient.Templates.GetTemplates(client.GetTemplatesRequest{
					Search: search,
					Folder: folder,
				})
				if err != nil {
					return errors.Wrap(err, "could not get templates")
				}
				renderJSON(response)
				return nil
			},
		},
		{
			Name:  "add",
			Usage: "add new template",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "update",
			Usage: "update an existing template",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing template",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "raw",
			Usage: "returns raw template contents",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
		{
			Name:  "execute",
			Usage: "executes an existing template",
			Action: func(c *cli.Context) error {
				return nil
			},
		},
	},
	Action: func(c *cli.Context) error {
		return nil
	},
}

var noColor bool

func renderJSON(item interface{}) {
	var buf bytes.Buffer
	_ = jsoniter.NewEncoder(&buf).Encode(item)

	var got []byte
	if !noColor {
		got = pretty.Color(buf.Bytes(), nil)
	} else {
		got = pretty.Pretty(buf.Bytes())
	}
	os.Stdout.Write(got)
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
