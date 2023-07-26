package testcore

import (
	"time"
)

type ItemType string

const (
	ItemStart ItemType = "start"
	ItemEnd   ItemType = "end"
)

type Item struct {
	ID           string
	Time         time.Time
	TemplateType string
	Target       string
	ItemType     ItemType
	Requests     int
}
