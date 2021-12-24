package main

import (
	"log"
	"os"

	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
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
					nucleiClient.Issues.GetIssue(id)
				}
				if search := c.String("search"); search != "" {
					nucleiClient.Issues.GetIssues(client.GetIssuesRequest{Search: search})
				}
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
			Action: func(c *cli.Context) error {
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

func main() {
	app := cli.NewApp()
	app.Usage = "Nuclei REST API Client"
	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "url", Usage: "Base URL of the Nuclei Server"},
		&cli.StringFlag{Name: "username", Usage: "Username of the Nuclei Server"},
		&cli.StringFlag{Name: "password", Usage: "Password of the Nuclei Server"},
	}
	// Initialize nuclei client before being used
	app.Before = cli.BeforeFunc(func(ctx *cli.Context) error {
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
