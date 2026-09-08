# Nuclei Runtime Reuse Milestone 1 Implementation Plan

> Execute this plan test-first. Do not begin scheduler rechunking until the baseline and worker-runtime gates at the end of this plan pass.

**Goal:** Remove confirmed repeated parsing/compilation and unbounded per-chunk compiled-cache retention from Aurora's Nuclei execution path, while producing trustworthy before/after timing, allocation, memory, and coverage evidence.

**Architecture:** A long-lived worker owns the parsed template cache and safe protocol infrastructure. Each concurrent scan execution receives a private parser with a private compiled cache, while sharing only immutable parsed template source. The execution cache is explicitly released at execution completion. Aurora's rate-limited batch loop uses the same ownership model and stops before starting another batch after cancellation.

**Tech stack:** Go, Nuclei SDK/core, Aurora worker, Prometheus, Go benchmarks, race detector, deterministic local HTTP/TLS fixtures.

**Design reference:** `docs/superpowers/specs/2026-09-08-aurora-nuclei-performance-design.md` in the Aurora `codex/aurora-nuclei-performance` worktree.

## Task 1: Add an explicit Nuclei execution-parser lifecycle

**Files:**

- Modify: `pkg/templates/parser.go`
- Modify: `pkg/templates/parser_purge_test.go`
- Modify: `pkg/templates/compile_bench_test.go`

### Step 1: Write failing lifecycle tests

Add tests proving that an execution parser:

- shares the parent's parsed cache;
- starts with an empty, private compiled cache;
- preserves parser validation/strictness settings;
- can purge its compiled cache without purging the parent's parsed cache;
- does not expose its compiled entries to a sibling execution parser.

Run:

```bash
go test ./pkg/templates -run 'TestParser.*Execution|TestParserPurgeCompiled' -count=1
```

Expected: FAIL because the explicit execution-parser and compiled-only purge APIs do not exist.

### Step 2: Implement the minimum lifecycle API

Add:

```go
func NewExecutionParser(parent *Parser) *Parser
func (p *Parser) PurgeCompiled()
```

`NewExecutionParser` must share only `parsedTemplatesCache`, copy parser behaviour flags, and allocate a new compiled cache. Reject or safely handle a nil parent. `PurgeCompiled` must never clear the shared parsed cache.

### Step 3: Run focused tests and race tests

```bash
go test ./pkg/templates -run 'TestParser.*Execution|TestParserPurge' -count=1
go test -race ./pkg/templates -run 'TestParser.*Execution|TestParserPurge' -count=1
```

Expected: PASS.

### Step 4: Extend the existing cache benchmark

Update `BenchmarkParseAcrossEngineLocalCaches` to use the public execution-parser lifecycle. Report allocation and timing results before and after the change without claiming scan-level improvement from this microbenchmark.

```bash
go test ./pkg/templates -run '^$' -bench BenchmarkParseAcrossEngineLocalCaches -benchmem -count=5
```

### Step 5: Commit

```bash
git add pkg/templates/parser.go pkg/templates/parser_purge_test.go pkg/templates/compile_bench_test.go
git commit -m "feat(templates): add execution-local parser lifecycle"
```

## Task 2: Make the thread-safe Nuclei SDK reuse parsed templates safely

**Files:**

- Modify: `lib/multi.go`
- Modify: `lib/multi_internal_test.go`
- Modify: `lib/multi_bench_test.go`
- Verify: `lib/result_callback_test.go`

### Step 1: Write failing SDK ownership tests

Test `createEphemeralObjects` directly and prove:

- each call receives a distinct execution parser;
- both parsers share the base parsed cache but not a compiled cache;
- caching is enabled within that isolated execution;
- closing ephemeral objects clears that execution's compiled cache;
- base and sibling caches remain intact;
- concurrent per-call output callbacks remain isolated.

Run:

```bash
go test ./lib -run 'TestEphemeral.*Parser|TestThreadSafe.*Callback' -count=1
```

Expected: FAIL because the current code reuses the base parser and sets `DoNotCache=true`.

### Step 2: Implement execution-local parser ownership

Create an execution parser from the long-lived engine parser in `createEphemeralObjects`, store its ownership in `unsafeOptions`, set it on `ExecutorOptions`, and allow caching inside the private execution cache. In `closeEphemeralObjects`, purge only that private compiled cache before removing inherited references.

Do not share compiled request objects across concurrent executions. Do not move output writers, credentials, variables, global matchers, workflow state, or rate limiters into the shared parser.

### Step 3: Run correctness and race tests

```bash
go test ./lib -run 'TestEphemeral.*Parser|TestThreadSafe|TestResult' -count=1
go test -race ./lib -run 'TestEphemeral.*Parser|TestThreadSafe|TestResult' -count=1
```

Expected: PASS with no race reports.

### Step 4: Capture SDK benchmark evidence

Run the existing repeated-execution benchmark on the parent revision and candidate revision with identical fixture and machine settings:

```bash
go test ./lib -run '^$' -bench BenchmarkExecuteNucleiWithOptsCtx -benchmem -count=10
```

Compare with `benchstat`. Record sec/op, B/op, and allocs/op. This is an SDK setup/execute benchmark, not yet an Aurora end-to-end result.

### Step 5: Commit

```bash
git add lib/multi.go lib/multi_internal_test.go lib/multi_bench_test.go
git commit -m "perf(lib): reuse parsed templates across isolated executions"
```

## Task 3: Add Aurora phase and terminal-reason observability

**Files:**

- Modify: `internal/agent/metrics/metrics.go`
- Modify: `internal/agent/nuclei/nuclei.go`
- Modify: `internal/agent/tasks.go`
- Modify: `internal/agent/tasks_test.go` or the nearest existing scan-settlement test
- Add: `internal/agent/nuclei/execution_metrics_test.go`

### Step 1: Write failing metric/terminal-reason tests

Tests must distinguish:

- Aurora chunk execution deadline;
- outer worker lifecycle timeout/cancellation;
- Nuclei core/batch deadline;
- target network timeout counted as an executed scan attempt rather than an orchestration timeout;
- normal completion and non-deadline execution failure.

Avoid new high-cardinality labels such as scan ID, target, or template ID.

### Step 2: Add bounded-cardinality metrics

Add counters/histograms for terminal reason and phase duration using fixed labels such as stream, phase, and reason. Time at least template discovery/load, compile/load-store, execute, output flush, and cleanup. Emit the same reason in structured logs.

### Step 3: Verify

```bash
GOWORK=off go test ./internal/agent/nuclei ./internal/agent -run 'Test.*ExecutionMetric|Test.*Settlement|Test.*Deadline' -count=1
```

Expected: PASS.

### Step 4: Commit

```bash
git add internal/agent/metrics/metrics.go internal/agent/nuclei internal/agent/tasks.go internal/agent/*test.go
git commit -m "feat(agent): expose nuclei execution phases and terminal reasons"
```

## Task 4: Bound Aurora rate-limited batch memory and honor cancellation

**Files:**

- Modify: `internal/agent/nuclei/nuclei.go`
- Add: `internal/agent/nuclei/rate_limited_batches_test.go`

### Step 1: Extract a testable sequential batch executor

Extract only the rate-limited batch loop behind a small internal function. Pass the loader/engine execution seam as a function so unit tests do not need live network services or a full Nuclei corpus.

### Step 2: Write failing behavioural tests

Cover only the confirmed boundaries:

- cancellation before a batch prevents that batch and every later batch from loading or executing;
- cancellation during a batch prevents the next batch from starting;
- each batch gets a private compiled cache backed by the process parsed cache;
- the previous batch compiled cache is empty/released before the next batch starts;
- every template path appears exactly once when no cancellation occurs;
- private templates/workflows retain the existing execute-once semantics.

### Step 3: Implement the bounded lifecycle

Before each batch, check `context.Cause(ctx)`. Create an execution parser with a private compiled cache for the batch, execute it, and explicitly purge the compiled cache on every exit path. Remove forced `runtime.GC()` from the hot loop only after the lifecycle tests prove cached objects are no longer retained.

Keep the current batch size initially. Changing batch size and cache ownership simultaneously would make the performance result ambiguous.

### Step 4: Verify

```bash
GOWORK=off go test ./internal/agent/nuclei -run 'TestRateLimitedBatch' -count=1
GOWORK=off go test -race ./internal/agent/nuclei -run 'TestRateLimitedBatch' -count=1
```

Expected: PASS.

### Step 5: Commit

```bash
git add internal/agent/nuclei/nuclei.go internal/agent/nuclei/rate_limited_batches_test.go
git commit -m "fix(agent): bound nuclei batch cache lifetime"
```

## Task 5: Build the deterministic milestone benchmark

**Files:**

- Add: `internal/agent/nuclei/tests/perfserver/server.go`
- Add: `internal/agent/nuclei/runtime_benchmark_test.go`
- Add: `scripts/scan-performance/run-milestone-1.sh`
- Add: `docs/benchmarks/aurora-nuclei-milestone-1.md`

### Step 1: Implement deterministic fixtures

Provide fixed fast, 100-ms, 500-ms, timeout, connection-reset, TLS, redirect, and multi-request endpoints. Track accepted connections and request identities. Use fixed seeds and local-only addresses.

### Step 2: Define the milestone coverage oracle

For this milestone, generate a seeded template/target manifest and compare expected server-observed attempts with worker terminal accounting. A target network timeout counts as a terminal attempt; missing or duplicated attempts fail. Full workflow/payload canonical-ledger support remains Workstream 1's next milestone and is not claimed here.

### Step 3: Capture baseline and candidate

Run at least five cold and ten warm repetitions using the same rate limit, template set, and concurrency. Capture:

- complete/missing/duplicate attempts;
- full-run wall time and attempts/second;
- process CPU time;
- peak RSS and RSS byte-seconds;
- heap allocations and GC count/pause;
- connections created and reused;
- compiled/parsed cache counts after each batch and run;
- Aurora versus target timeout reasons.

### Step 4: Apply the milestone gate

Proceed to deadline-fit scheduler work only if:

- the candidate has zero missing or duplicate attempts;
- no Aurora/core deadline expires in the deterministic matrix;
- repeated-run compiled-cache size is bounded by the active batch/execution;
- wall time and attempts/second do not regress;
- CPU-seconds and RSS byte-seconds improve.

### Step 5: Commit evidence

```bash
git add internal/agent/nuclei/tests/perfserver internal/agent/nuclei/runtime_benchmark_test.go scripts/scan-performance docs/benchmarks/aurora-nuclei-milestone-1.md
git commit -m "test(agent): add nuclei runtime performance benchmark"
```

## Task 6: Milestone verification and handoff

Run:

```bash
go test ./pkg/templates ./lib -count=1
go test -race ./pkg/templates ./lib -count=1
GOWORK=off go test ./internal/agent/nuclei ./internal/agent -count=1
GOWORK=off go test -race ./internal/agent/nuclei -count=1
```

Then run the deterministic benchmark and record the exact commands, revisions, machine limits, and raw summary in the benchmark document.

Do not claim the overall zero-deadline goal at this milestone. The milestone claim is limited to safe runtime reuse, bounded batch memory, cancellation correctness, and demonstrated local performance. The next implementation plan covers canonical attempt accounting, deadline-fit chunking, capacity-aware admission, and work-based fleet sizing.

