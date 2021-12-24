package main

import "github.com/urfave/cli/v2"

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
}
