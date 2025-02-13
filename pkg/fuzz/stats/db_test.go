package stats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewStatsDatabase(t *testing.T) {
	db, err := NewSimpleStats()
	require.NoError(t, err)

	err = db.InsertMatchedRecord(FuzzingEvent{
		URL:           "http://localhost:8080/login",
		TemplateID:    "apache-struts2-001",
		ComponentType: "path",
		ComponentName: "/login",
		PayloadSent:   "/login'\"><",
		StatusCode:    401,
	})
	require.NoError(t, err)

	//os.Remove("test.stats.db")
}
