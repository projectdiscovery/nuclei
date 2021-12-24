package main

import (
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
	"github.com/urfave/cli/v2"
)

var settings = &cli.Command{
	Name:  "settings",
	Usage: "setting related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns setting(s) from server",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "name", Usage: "name of setting to retrieve"},
			},
			Action: func(c *cli.Context) error {
				if name := c.String("name"); name != "" {
					setting, err := nucleiClient.Settings.GetSetting(name)
					if err != nil {
						return errors.Wrap(err, "could not get setting by name")
					}
					return renderJSON(setting)
				}
				settings, err := nucleiClient.Settings.GetSettings()
				if err != nil {
					return errors.Wrap(err, "could not get settings")
				}
				return renderJSON(settings)
			},
		},
		{
			Name:  "update",
			Usage: "updates an existing setting",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "name", Usage: "name of setting to add"},
				&cli.StringFlag{Name: "filepath", Usage: "path of setting to add"},
				&cli.StringFlag{Name: "type", Usage: "type of setting to add"},
			},
			Action: func(c *cli.Context) error {
				data, err := ioutil.ReadFile(c.String("filepath"))
				if err != nil {
					return errors.Wrap(err, "could not read settings")
				}
				err = nucleiClient.Settings.UpdateSetting(client.UpdateSettingRequest{
					Name:     c.String("name"),
					Contents: string(data),
					Type:     c.String("type"),
				})
				if err != nil {
					return errors.Wrap(err, "could not update setting")
				}
				return renderJSON("updated setting successfully")
			},
		},
		{
			Name:  "add",
			Usage: "add a new setting to storage",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "name", Usage: "name of setting to add"},
				&cli.StringFlag{Name: "filepath", Usage: "path of setting to add"},
				&cli.StringFlag{Name: "type", Usage: "type of setting to add"},
			},
			Action: func(c *cli.Context) error {
				data, err := ioutil.ReadFile(c.String("filepath"))
				if err != nil {
					return errors.Wrap(err, "could not read settings")
				}
				err = nucleiClient.Settings.AddSetting(client.AddSettingRequest{
					Name:     c.String("name"),
					Contents: string(data),
					Type:     c.String("type"),
				})
				if err != nil {
					return errors.Wrap(err, "could not add setting")
				}
				return renderJSON("added setting successfully")
			},
		},
	},
}
