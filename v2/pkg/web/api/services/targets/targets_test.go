package targets

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTargetsNewLineCountWriter(t *testing.T) {
	writer := &NewLineCountWriter{}
	writer.Write([]byte("test\ntest2\n"))
	require.Equal(t, int64(2), writer.Total, "could not get total newline writes")
}

func TestTargetsStore(t *testing.T) {
	tempdir, err := ioutil.TempDir("", "test-dir-*")
	require.Nil(t, err, "could not create tempdir")
	defer os.RemoveAll(tempdir)

	storage := NewTargetsStorage(tempdir)

	var gotID string
	t.Run("create", func(t *testing.T) {
		writer, id, err := storage.Create()
		require.Nil(t, err, "could not create storage file")
		gotID = id
		_, _ = writer.Write([]byte("abcd"))
		writer.Close()
	})
	t.Run("read", func(t *testing.T) {
		reader, err := storage.Read(gotID)
		require.Nil(t, err, "could not read storage file")

		data, _ := ioutil.ReadAll(reader)
		require.Equal(t, string("abcd"), string(data), "could not read correct data")
	})
	t.Run("update", func(t *testing.T) {
		updater, err := storage.Update(gotID)
		require.Nil(t, err, "could not read storage file")
		_, _ = updater.Write([]byte("ggwp"))
		updater.Close()

		reader, err := storage.Read(gotID)
		require.Nil(t, err, "could not read storage file")

		data, _ := ioutil.ReadAll(reader)
		require.Equal(t, string("abcdggwp"), string(data), "could not read correct data")
	})
	t.Run("delete", func(t *testing.T) {
		err := storage.Delete(gotID)
		require.Nil(t, err, "could not delete storage file")
	})
}
