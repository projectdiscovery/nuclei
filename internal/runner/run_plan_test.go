package runner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPlanRunResumesFromItsDoneLog(t *testing.T) {
	planFile := filepath.Join(t.TempDir(), "plan.jsonl")
	require.NoError(t, os.WriteFile(planFile, []byte(`{"id":"00000000000000a1","target":"https://a.example/x","templates":["root"]}
{"id":"00000000000000a2","target":"https://a.example/y","templates":["root"],"alternative-to":"00000000000000a1"}
{"id":"00000000000000b1","target":"https://b.example","templates":["generic"]}
{"id":"00000000000000c1","target":"https://c.example","templates":["generic"]}
{"summary":{"entries":3,"alternatives":1}}
`), 0o644))
	// the last line was cut off by an interrupted write
	require.NoError(t, os.WriteFile(planDoneLog(planFile), []byte("00000000000000b1\n00000000"), 0o644))

	run, err := openPlanRun(planFile)
	require.NoError(t, err)
	require.Len(t, run.entries, 4)
	require.Equal(t, 1, run.resumed)

	require.True(t, run.Skip("00000000000000b1"), "finished in the previous run")
	require.True(t, run.Skip("00000000000000ff"), "not in the plan")
	require.False(t, run.Skip("00000000000000a1"))
	run.Finished("00000000000000a1")
	require.True(t, run.Skip("00000000000000a2"), "its origin is covered")
	require.Equal(t, 1, run.unreached(), "c1 never ran")
	require.NoError(t, run.close())

	log, err := os.ReadFile(planDoneLog(planFile))
	require.NoError(t, err)
	require.Equal(t, "00000000000000b1\n00000000\n00000000000000a1\n", string(log), "the partial line is not extended")

	again, err := openPlanRun(planFile)
	require.NoError(t, err)
	require.Equal(t, 3, again.resumed, "b1, and a1 with its alternative")
	require.True(t, again.Skip("00000000000000a2"), "a finished origin stays covered")
	require.False(t, again.Skip("00000000000000c1"))
	require.NoError(t, again.close())
}

func TestPlanRunRejectsAMalformedPlan(t *testing.T) {
	planFile := filepath.Join(t.TempDir(), "plan.jsonl")
	require.NoError(t, os.WriteFile(planFile, []byte("{\"id\":\"00000000000000a1\"}\nnot json\n"), 0o644))
	_, err := openPlanRun(planFile)
	require.ErrorContains(t, err, "plan.jsonl:2")
}

func TestPlanRunFollowsAppendsAndCancels(t *testing.T) {
	planFile := filepath.Join(t.TempDir(), "plan.jsonl")
	require.NoError(t, os.WriteFile(planFile, []byte(`{"id":"00000000000000a1","target":"https://a.example/x","templates":["root"]}
{"id":"00000000000000a2","target":"https://a.example/y","templates":["root"],"alternative-to":"00000000000000a1"}
{"id":"00000000000000b1","target":"https://b.example","templates":["generic"]}
`), 0o644))
	require.NoError(t, os.WriteFile(planCancelLog(planFile), []byte("00000000000000b1\n"), 0o644))

	run, err := openPlanRun(planFile)
	require.NoError(t, err)
	require.True(t, run.Skip("00000000000000b1"), "cancelled before the run")

	appendTo := func(path, text string) {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		require.NoError(t, err)
		_, err = file.WriteString(text)
		require.NoError(t, err)
		require.NoError(t, file.Close())
	}
	var errs []error
	collect := func(err error) { errs = append(errs, err) }

	appendTo(planFile, "{\"id\":\"00000000000000c1\",\"target\":\"https://c.example\",\"templates\":[\"generic\"]}\nnot json\n{\"id\":\"00000000000000d1\"")
	appendTo(planCancelLog(planFile), "00000000000000a1\n")
	run.poll(collect)
	require.Len(t, errs, 1)
	require.ErrorContains(t, errs[0], "plan.jsonl:5")
	require.False(t, run.Skip("00000000000000c1"), "appended")
	require.True(t, run.Skip("00000000000000d1"), "still being written")
	require.True(t, run.Skip("00000000000000a2"), "its group is cancelled")

	appendTo(planFile, ",\"target\":\"https://d.example\",\"templates\":[\"generic\"]}\n")
	run.follow(time.Millisecond, collect)
	require.Eventually(t, func() bool { return !run.Skip("00000000000000d1") }, time.Second, time.Millisecond)
	require.NoError(t, run.close())
	require.Equal(t, 0, run.unreached(), "cancelled entries are not unreached")
	require.Len(t, errs, 1)
}
