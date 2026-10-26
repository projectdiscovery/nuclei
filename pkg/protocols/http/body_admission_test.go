package http

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/utils/memguardian"
	"github.com/stretchr/testify/require"
)

func TestLargeBodyAdmissionUsesMemoryBudget(t *testing.T) {
	admission := newBodyAdmission(3 << 30)
	require.EqualValues(t, 48<<20, admission.limit)

	releases := make([]func(), 0, 2)
	for range 2 {
		release, err := admission.acquire(t.Context(), 20<<20)
		require.NoError(t, err)
		releases = append(releases, release)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := admission.acquire(ctx, 20<<20)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	releases[0]()
	release, err := admission.acquire(t.Context(), 20<<20)
	require.NoError(t, err)
	release()
	releases[1]()
}

func TestSystemBodyAdmissionRespectsCgroupLimit(t *testing.T) {
	raw, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		t.Skipf("cgroup v2 memory limit unavailable: %v", err)
	}
	limit, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		t.Skipf("cgroup v2 has no finite memory limit: %v", err)
	}
	info, err := memguardian.GetSysInfo()
	require.NoError(t, err)
	expected := newBodyAdmission(min(limit, info.TotalRam())).limit
	actual := systemBodyAdmission().limit
	require.Equalf(t, expected, actual, "body admission must use the lower of host RAM and %d-byte cgroup limit", limit)
}

func TestCgroupMemoryLimit(t *testing.T) {
	for _, test := range []struct {
		name, membership string
		files            map[string]string
		want             uint64
		wantError        bool
	}{
		{name: "v2 namespaced root", membership: "0::/\n", files: map[string]string{"memory.max": "536870912\n"}, want: 512 << 20},
		{name: "v2 parent bound", membership: "0::/tenant/pod\n", files: map[string]string{"memory.max": "max\n", "tenant/memory.max": "1073741824\n", "tenant/pod/memory.max": "2147483648\n"}, want: 1 << 30},
		{name: "v2 unlimited", membership: "0::/\n", files: map[string]string{"memory.max": "max\n"}},
		{name: "v1 memory controller", membership: "5:cpu,memory:/pod\n4:cpu:/pod\n", files: map[string]string{"memory/memory.limit_in_bytes": "max\n", "memory/pod/memory.limit_in_bytes": "268435456\n"}, want: 256 << 20},
		{name: "invalid bound", membership: "0::/\n", files: map[string]string{"memory.max": "invalid\n"}, wantError: true},
		{name: "no membership", membership: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			membershipPath := filepath.Join(root, "self-cgroup")
			require.NoError(t, os.WriteFile(membershipPath, []byte(test.membership), 0o600))
			for name, contents := range test.files {
				path := filepath.Join(root, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
				require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
			}
			limit, err := cgroupMemoryLimit(membershipPath, root)
			if test.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, limit)
		})
	}
}

func TestSmallBodyBypassesLargeBodyAdmission(t *testing.T) {
	admission := newBodyAdmission(3 << 30)
	fullRelease, err := admission.acquire(t.Context(), admission.limit)
	require.NoError(t, err)
	defer fullRelease()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	release, err := admission.acquire(ctx, largeBodyThreshold-1)
	require.NoError(t, err)
	release()
}
