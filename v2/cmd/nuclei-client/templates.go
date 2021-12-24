package main

import (
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
	"github.com/urfave/cli/v2"
)

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
				return renderJSON(response)
			},
		},
		{
			Name:  "add",
			Usage: "add new template",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "path for the template"},
				&cli.StringFlag{Name: "filepath", Usage: "local path to the template"},
				&cli.StringFlag{Name: "folder", Usage: "folder for the template"},
			},
			Action: func(c *cli.Context) error {
				data, err := ioutil.ReadFile(c.String("filepath"))
				if err != nil {
					return errors.Wrap(err, "could not read template")
				}
				id, err := nucleiClient.Templates.AddTemplate(client.AddTemplateRequest{
					Contents: string(data),
					Path:     c.String("path"),
					Folder:   c.String("folder"),
				})
				if err != nil {
					return errors.Wrap(err, "could not add template")
				}
				return renderJSON(id)
			},
		},
		{
			Name:  "update",
			Usage: "update an existing template",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "path for the template"},
				&cli.StringFlag{Name: "filepath", Usage: "local path to the template"},
			},
			Action: func(c *cli.Context) error {
				data, err := ioutil.ReadFile(c.String("filepath"))
				if err != nil {
					return errors.Wrap(err, "could not read template")
				}
				err = nucleiClient.Templates.UpdateTemplate(client.UpdateTemplateRequest{
					Contents: string(data),
					Path:     c.String("path"),
				})
				if err != nil {
					return errors.Wrap(err, "could not update template")
				}
				return renderJSON("template updated successfully")
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing template",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "path for the template"},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Templates.DeleteTemplate(client.DeleteTemplateRequest{
					Path: c.String("path"),
				})
				if err != nil {
					return errors.Wrap(err, "could not delete template")
				}
				return renderJSON("template deleted successfully")
			},
		},
		{
			Name:  "raw",
			Usage: "returns raw template contents",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "path for the template"},
			},
			Action: func(c *cli.Context) error {
				contents, err := nucleiClient.Templates.GetTemplateRaw(c.String("path"))
				if err != nil {
					return errors.Wrap(err, "could not get raw template")
				}
				fmt.Printf("%s\n", contents)
				return nil
			},
		},
		{
			Name:  "execute",
			Usage: "executes an existing template",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "path", Usage: "path for the template"},
				&cli.StringFlag{Name: "target", Usage: "target for the template"},
			},
			Action: func(c *cli.Context) error {
				data, err := nucleiClient.Templates.ExecuteTemplate(client.ExecuteTemplateRequest{
					Path:   c.String("path"),
					Target: c.String("target"),
				})
				if err != nil {
					return errors.Wrap(err, "could not execute template")
				}
				return renderJSON(data)
			},
		},
	},
}
