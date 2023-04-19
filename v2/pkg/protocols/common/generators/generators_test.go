package generators

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
)

func TestBatteringRamGenerator(t *testing.T) {
	usernames := []string{"admin", "password"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames}, BatteringRamAttack, "", false, catalogInstance, "")
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	count := 0
	for {
		_, ok := iterator.Value()
		if !ok {
			break
		}
		count++
	}
	require.Equal(t, len(usernames), count, "could not get correct batteringram counts")
}

func TestPitchforkGenerator(t *testing.T) {
	usernames := []string{"admin", "token"}
	passwords := []string{"password1", "password2", "password3"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames, "password": passwords}, PitchForkAttack, "", false, catalogInstance, "")
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	count := 0
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		count++
		require.Contains(t, usernames, value["username"], "Could not get correct pitchfork username")
		require.Contains(t, passwords, value["password"], "Could not get correct pitchfork password")
	}
	require.Equal(t, len(usernames), count, "could not get correct pitchfork counts")
}

func TestClusterbombGenerator(t *testing.T) {
	usernames := []string{"admin"}
	passwords := []string{"admin", "password", "token"}

	catalogInstance := disk.NewCatalog("")
	generator, err := New(map[string]interface{}{"username": usernames, "password": passwords}, ClusterBombAttack, "", false, catalogInstance, "")
	require.Nil(t, err, "could not create generator")

	iterator := generator.NewIterator()
	count := 0
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		count++
		require.Contains(t, usernames, value["username"], "Could not get correct clusterbomb username")
		require.Contains(t, passwords, value["password"], "Could not get correct clusterbomb password")
	}
	require.Equal(t, 3, count, "could not get correct clusterbomb counts")

	iterator.Reset()
	count = 0
	for {
		value, ok := iterator.Value()
		if !ok {
			break
		}
		count++
		require.Contains(t, usernames, value["username"], "Could not get correct clusterbomb username")
		require.Contains(t, passwords, value["password"], "Could not get correct clusterbomb password")
	}
	require.Equal(t, 3, count, "could not get correct clusterbomb counts")
}
