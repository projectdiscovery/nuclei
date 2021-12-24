package main

import "github.com/urfave/cli/v2"

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
