package scans

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"github.com/stretchr/testify/require"
)

func TestInputProviderFromRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tempdir, err := ioutil.TempDir("", "test-data-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempdir)

	targetsStorage := targets.NewTargetsStorage(tempdir)
	querier := db.NewMockQuerier(ctrl)
	s := NewScanService(tempdir, 1, querier, targetsStorage)

	t.Run("url", func(t *testing.T) {
		provider, err := s.inputProviderFromRequest([]string{"https://uber.com"})
		require.NoError(t, err, "could not get input provider from url")

		var got string
		provider.Scan(func(value string) bool {
			got = value
			return true
		})
		require.Equal(t, "https://uber.com", got, "could not get correct target from url provider")
	})

	t.Run("id", func(t *testing.T) {
		id := int64(1)
		writer, internalID, err := targetsStorage.Create()
		_, _ = writer.Write([]byte("1.1.1.1\n1.0.0.1"))
		writer.Close()
		require.NoError(t, err, "could not write target to storage")

		querier.EXPECT().
			GetTarget(gomock.Any(), gomock.Eq(id)).
			Times(1).
			Return(dbsql.GetTargetRow{Internalid: internalID}, nil)

		provider, err := s.inputProviderFromRequest([]string{"1"})
		require.NoError(t, err, "could not get input provider from url")

		var got []string
		provider.Scan(func(value string) bool {
			got = append(got, value)
			return true
		})
		require.ElementsMatch(t, []string{"1.1.1.1", "1.0.0.1"}, got, "could not get correct target from storage")
	})
}

func TestStoreTemplatesFromRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tempdir, err := ioutil.TempDir("", "test-data-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempdir)

	targetsStorage := targets.NewTargetsStorage(tempdir)
	querier := db.NewMockQuerier(ctrl)
	s := NewScanService(tempdir, 1, querier, targetsStorage)

	results := []dbsql.GetTemplatesForScanRow{
		{Path: "cves/2021/test.yaml", Contents: "id: test"},
		{Path: "cves/2020/workflow.yaml", Contents: "id: test\nworkflow:\n"},
	}
	querier.EXPECT().
		GetTemplatesForScan(gomock.Any(), gomock.Eq("cves/")).
		Times(1).
		Return(results, nil)

	directory, templates, workflows, err := s.storeTemplatesFromRequest([]string{"cves/"})
	defer os.RemoveAll(directory)

	require.NoError(t, err, "could not get templates from request")
	require.Equal(t, []string{"cves/2021/test.yaml"}, templates, "could not get correct templates")
	require.Equal(t, []string{"cves/2020/workflow.yaml"}, workflows, "could not get correct workflows")
}
