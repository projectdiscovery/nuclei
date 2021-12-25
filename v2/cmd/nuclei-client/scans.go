package main

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/client"
	"github.com/urfave/cli/v2"
)

var scans = &cli.Command{
	Name:  "scans",
	Usage: "scan related apis",
	Subcommands: []*cli.Command{
		{
			Name:  "get",
			Usage: "returns list of scan(s)",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the scan"},
				&cli.StringFlag{Name: "search", Usage: "search key for the scans"},
			},
			Action: func(c *cli.Context) error {
				if id := c.Int64("id"); id != 0 {
					if scan, err := nucleiClient.Scans.GetScan(id); err != nil {
						return errors.Wrap(err, "could not get scan")
					} else {
						return renderJSON(scan)
					}
				}
				scans, err := nucleiClient.Scans.GetScans(client.GetScansRequest{
					Search: c.String("search"),
				})
				if err != nil {
					return errors.Wrap(err, "could not get scans")
				}
				return renderJSON(scans)
			},
		},
		{
			Name:  "add",
			Usage: "adds a new scan to queue",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "name", Usage: "name of scan to add"},
				&cli.StringSliceFlag{Name: "templates", Usage: "templates for the scan"},
				&cli.StringSliceFlag{Name: "targets", Usage: "targets for the scan"},
				&cli.StringFlag{Name: "config", Usage: "config for the scan", Value: "default"},
				&cli.BoolFlag{Name: "run", Usage: "run the scan instantly"},
				&cli.StringFlag{Name: "reporting", Usage: "reporting config for the scan"},
				&cli.StringFlag{Name: "schedule-occurence", Usage: "schedule occurence for the scan"},
				&cli.StringFlag{Name: "schedule-time", Usage: "schedule time for the scan"},
				&cli.StringFlag{Name: "scan-source", Usage: "source of the scan", Value: "CLI"},
			},
			Action: func(c *cli.Context) error {
				id, err := nucleiClient.Scans.AddScan(client.AddScanRequest{
					Name:              c.String("name"),
					Templates:         c.StringSlice("templates"),
					Targets:           c.StringSlice("targets"),
					Config:            c.String("config"),
					RunNow:            c.Bool("run"),
					Reporting:         c.String("reporting"),
					ScheduleOccurence: c.String("schedule-occurence"),
					ScheduleTime:      c.String("schedule-time"),
					ScanSource:        c.String("scan-source"),
				})
				if err != nil {
					return errors.Wrap(err, "could not add scan")
				}
				return renderJSON(id)
			},
		},
		{
			Name:  "progress",
			Usage: "returns running scan progress",
			Action: func(c *cli.Context) error {
				progress, err := nucleiClient.Scans.GetScanProgress()
				if err != nil {
					return errors.Wrap(err, "could not get scan progress")
				}
				return renderJSON(progress)
			},
		},
		{
			Name:  "update",
			Usage: "update an existing scan",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the scan"},
				&cli.BoolFlag{Name: "stop", Usage: "stop a specific scan"},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Scans.UpdateScan(c.Int64("id"), client.UpdateScanRequest{
					Stop: c.Bool("stop"),
				})
				if err != nil {
					return errors.Wrap(err, "could not update scan")
				}
				return renderJSON("updated scan successfully")
			},
		},
		{
			Name:  "delete",
			Usage: "delete an existing scan",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the scan"},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Scans.DeleteScan(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not delete scan")
				}
				return renderJSON("deleted scan successfully")

			},
		},
		{
			Name:  "execute",
			Usage: "execute an existing scan",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the scan"},
			},
			Action: func(c *cli.Context) error {
				err := nucleiClient.Scans.ExecuteScan(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not execute scan")
				}
				return renderJSON("executed scan successfully")
			},
		},
		{
			Name:  "matches",
			Usage: "matches for an existing scan",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the scan"},
			},
			Action: func(c *cli.Context) error {
				matches, err := nucleiClient.Scans.GetScanMatches(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not get scan matches")
				}
				return renderJSON(matches)
			},
		},
		{
			Name:  "errors",
			Usage: "errors for an existing scan",
			Flags: []cli.Flag{
				&cli.Int64Flag{Name: "id", Usage: "id of the scan"},
			},
			Action: func(c *cli.Context) error {
				errorsList, err := nucleiClient.Scans.GetScanErrors(c.Int64("id"))
				if err != nil {
					return errors.Wrap(err, "could not get scan errors")
				}
				return renderJSON(errorsList)
			},
		},
	},
}
