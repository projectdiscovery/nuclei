package main

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
	"github.com/urfave/cli/v2"
)

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
					resp, err := nucleiClient.Issues.GetIssue(id)
					if err != nil {
						return errors.Wrap(err, "could not get issue for id")
					}
					return renderJSON(resp)
				}
				search := c.String("search")
				response, err := nucleiClient.Issues.GetIssues(client.GetIssuesRequest{Search: search})
				if err != nil {
					return errors.Wrap(err, "could not get issues")
				}
				return renderJSON(response)
			},
		},
		//	{
		//		Name:  "add",
		//		Usage: "add a new issue to list",
		//		Action: func(c *cli.Context) error {
		//			return nil
		//		},
		//	},
		{
			Name:  "update",
			Usage: "update an existing issue",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "state", Usage: "updated state of the issue"},
				&cli.Int64Flag{Name: "id", Usage: "ID of the issue"},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Issues.UpdateIssue(c.Int64("id"), client.UpdateIssueRequest{
					State: c.String("state"),
				})
				if err != nil {
					return errors.Wrap(err, "could not update issue")
				}
				return renderJSON("updated issue successfully")
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing issue",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "ID of the issue"},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Issues.DeleteIssue(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not delete issue")
				}
				return renderJSON("deleted issue successfully")
			},
		},
	},
}
