package stats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewStatsDatabase(t *testing.T) {
	db, err := NewSqliteStatsDatabase("test")
	require.NoError(t, err)

	err = db.InsertComponent(FuzzingEvent{
		URL:           "http://localhost:8080/login",
		SiteName:      "localhost:8080",
		TemplateID:    "apache-struts2-001",
		ComponentType: "path",
		ComponentName: "/login",
		PayloadSent:   "/login'\"><",
		StatusCode:    401,
	})
	require.NoError(t, err)

	var siteName string
	err = db.db.QueryRow("SELECT template_name FROM templates WHERE template_id = 1").Scan(&siteName)
	require.NoError(t, err)
	require.Equal(t, "apache-struts2-001", siteName)

	err = db.InsertMatchedRecord(FuzzingEvent{
		URL:           "http://localhost:8080/login",
		SiteName:      "localhost:8080",
		TemplateID:    "apache-struts2-001",
		ComponentType: "path",
		ComponentName: "/login",
		PayloadSent:   "/login'\"><",
		StatusCode:    401,
		Matched:       true,
	})
	require.NoError(t, err)

	db.Close()

	//os.Remove("test.stats.db")
}
