package main

import (
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/api/client"
	"github.com/urfave/cli/v2"
)

var targets = &cli.Command{
	Name:  "targets",
	Usage: "target related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns list of targets",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "search", Usage: "search key for the targets"},
				&cli.IntFlag{Name: "page", Usage: "page for the db query pagination"},
				&cli.IntFlag{Name: "size", Usage: "size for the db query pagination"},
			},
			Action: func(c *cli.Context) error {
				targets, err := nucleiClient.Targets.GetTargets(client.GetTargetsRequest{
					Search: c.String("search"),
					Page:   c.Int("page"),
					Size:   c.Int("size"),
				})
				if err != nil {
					return errors.Wrap(err, "could not get targets")
				}
				return renderJSON(targets)
			},
		},
		{
			Name:  "add",
			Usage: "add a new target",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "path of the target", Required: true},
				&cli.StringFlag{Name: "name", Usage: "name of the target", Required: true},
				&cli.StringFlag{Name: "filepath", Usage: "filepath of the target list", Required: true},
			},
			Action: func(c *cli.Context) error {
				file, err := os.Open(c.String("filepath"))
				if err != nil {
					return errors.Wrap(err, "could not read targets")
				}
				defer file.Close()

				id, err := nucleiClient.Targets.AddTarget(client.AddTargetRequest{
					Name:     c.String("name"),
					Path:     c.String("path"),
					Contents: file,
				})
				if err != nil {
					return errors.Wrap(err, "could not add target")
				}
				return renderJSON(id)

			},
		},
		{
			Name:  "update",
			Usage: "update an existing target",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the target", Required: true},
				&cli.StringFlag{Name: "filepath", Usage: "filepath of the target list", Required: true},
			},
			Action: func(c *cli.Context) error {
				file, err := os.Open(c.String("filepath"))
				if err != nil {
					return errors.Wrap(err, "could not read targets")
				}
				defer file.Close()

				err = nucleiClient.Targets.UpdateTarget(client.UpdateTargetRequest{
					ID:       c.Int64("id"),
					Contents: file,
				})
				if err != nil {
					return errors.Wrap(err, "could not update target")
				}
				return renderJSON("updated target successfully")
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing target",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the target", Required: true},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Targets.DeleteTarget(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not delete target")
				}
				return renderJSON("deleted target successfully")
			},
		},
		{
			Name:  "contents",
			Usage: "contents for an existing target",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the target", Required: true},
			},
			Action: func(c *cli.Context) error {
				contents, err := nucleiClient.Targets.GetTargetContents(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not get target")
				}
				_, _ = io.Copy(os.Stdout, contents)
				contents.Close()
				return nil
			},
		},
	},
}
