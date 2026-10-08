# ThreatLocker Session Preload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preload fresh ThreatLocker inventories and cleanup analysis during each authenticated session so opening the page does not expose the portal's full latency.

> **Status reconciliation — 2026-08-18:** Implemented by commits `1cf6098`,
> `2e0275d`, `5d70563`, `ad50e9a`, and `f18a451`. The session query store,
> bounded preloader, shared backend snapshot, forced refresh path, tests, and
> timeout fix are all on `main`. The unchecked boxes below preserve the
> original execution recipe; they are not open work.

**Architecture:** A reusable frontend session query store owns cached values, errors, subscriptions, and in-flight request deduplication. An authenticated coordinator refreshes six ThreatLocker datasets with concurrency two, while a 60-second backend application snapshot lets the Apps and cleanup-candidate routes share one portal inventory request.

**Tech Stack:** React 18, TypeScript 5.6, Node test runner, Go 1.26, Chi, `golang.org/x/sync/singleflight`, Nginx, Docker Compose.

## Global Constraints

- ThreatLocker browser data is memory-only and must be cleared on logout.
- No browser data may survive into a later login session.
- Background refresh interval is exactly 60 seconds.
- At most two preload tasks may execute concurrently.
- Manual refresh must bypass cached frontend and backend inventory.
- What-If, execute, verification, and other ThreatLocker writes remain uncached.
- Failed portal calls are never retained as successful cache values.
- Preserve the existing `NOT_CONNECTED` behavior and all authorization middleware.
- Operate only on the `rtm` Compose project when deploying to demo.

---

### Task 1: Session query store with in-flight deduplication

**Files:**
- Create: `frontend/src/api/sessionQueryStore.ts`
- Create: `frontend/tests/sessionQueryStore.test.ts`
- Modify: `frontend/src/api/hooks.ts`

**Interfaces:**
- Produces: `loadSessionQuery<T>(key: string, loader: () => Promise<T>, options?: { force?: boolean }): Promise<T>`
- Produces: `readSessionQuery<T>(key: string): SessionQuerySnapshot<T>`
- Produces: `subscribeSessionQuery(key: string, listener: () => void): () => void`
- Produces: `clearSessionQueries(prefix?: string): void`
- Consumes: existing `useRefreshingAsync` cache keys and loaders.

- [ ] **Step 1: Write failing store tests**

Create tests that prove one loader call is shared by two consumers, a successful
value can be read synchronously, force invokes a new loader, failure is
retryable, subscribers receive completion, and clear removes ThreatLocker data:

```ts
test("deduplicates concurrent consumers and publishes the value", async () => {
  let calls = 0;
  let release!: (value: string[]) => void;
  const loader = () => {
    calls += 1;
    return new Promise<string[]>((resolve) => { release = resolve; });
  };
  const first = loadSessionQuery("threatlocker:apps", loader);
  const second = loadSessionQuery("threatlocker:apps", loader);
  release(["app-1"]);
  assert.deepEqual(await first, ["app-1"]);
  assert.deepEqual(await second, ["app-1"]);
  assert.equal(calls, 1);
  assert.deepEqual(readSessionQuery<string[]>("threatlocker:apps").data, ["app-1"]);
});

test("clear removes current-session ThreatLocker values", async () => {
  await loadSessionQuery("threatlocker:apps", async () => ["app-1"]);
  clearSessionQueries("threatlocker:");
  assert.equal(readSessionQuery("threatlocker:apps").data, undefined);
});
```

- [ ] **Step 2: Run the store tests and verify RED**

Run: `node --test tests/sessionQueryStore.test.ts`

Expected: FAIL because `sessionQueryStore.ts` does not exist.

- [ ] **Step 3: Implement the store**

Use one entry per key with `data`, `error`, `inFlight`, and listeners. Join an
existing promise unless `force` is true; publish success or error to listeners;
delete the entry's successful value on clear. A generation counter must prevent
a promise started before logout from repopulating the next session:

```ts
export interface SessionQuerySnapshot<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  refreshing: boolean;
}

export function loadSessionQuery<T>(
  key: string,
  loader: () => Promise<T>,
  options: { force?: boolean } = {},
): Promise<T>;
export function readSessionQuery<T>(key: string): SessionQuerySnapshot<T>;
export function subscribeSessionQuery(key: string, listener: () => void): () => void;
export function clearSessionQueries(prefix?: string): void;
```

- [ ] **Step 4: Refactor `useRefreshingAsync` onto the store**

Initialize from `readSessionQuery`, subscribe on mount, call
`loadSessionQuery` from the effect, and make `refresh()` force a new request.
Preserve visible data during refresh and preserve the public
`RefreshingAsyncState<T>` interface.

- [ ] **Step 5: Run frontend tests and build**

Run: `npm test && npm run build`

Expected: all tests PASS and Vite production build succeeds.

- [ ] **Step 6: Commit the query-store task**

```bash
git add frontend/src/api/sessionQueryStore.ts frontend/src/api/hooks.ts frontend/tests/sessionQueryStore.test.ts
git commit -m "feat: add session query store"
```

### Task 2: Authenticated ThreatLocker preload coordinator

**Files:**
- Create: `frontend/src/features/threatlocker/preload.ts`
- Create: `frontend/src/features/threatlocker/ThreatLockerPreloader.tsx`
- Create: `frontend/tests/threatlockerPreload.test.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/store/auth.tsx`
- Modify: `frontend/src/features/threatlocker/ThreatLockerPage.tsx`
- Modify: `frontend/src/features/threatlocker/CleanupTab.tsx`

**Interfaces:**
- Consumes: Task 1's `loadSessionQuery` and `clearSessionQueries`.
- Produces: `runThreatLockerPreload(loaders: ThreatLockerPreloadLoaders, concurrency?: number): Promise<void>`
- Produces: `<ThreatLockerPreloader />`, mounted only inside authenticated providers.

- [ ] **Step 1: Write failing preload scheduling tests**

Use deferred loaders to prove Apps and Devices start first, no more than two
loaders run concurrently, every dataset is attempted after earlier work
settles, and a rejected loader does not stop later tasks:

```ts
test("preloads all ThreatLocker datasets with concurrency two", async () => {
  let active = 0;
  let maximum = 0;
  const started: string[] = [];
  const loader = (name: string) => async () => {
    started.push(name);
    active += 1;
    maximum = Math.max(maximum, active);
    await Promise.resolve();
    active -= 1;
  };
  await runThreatLockerPreload({
    apps: loader("apps"),
    devices: loader("devices"),
    policies: loader("policies"),
    approvals: loader("approvals"),
    cleanupOperations: loader("cleanup-operations"),
    cleanupCandidates: loader("cleanup-candidates"),
  });
  assert.deepEqual(started.slice(0, 2), ["apps", "devices"]);
  assert.equal(maximum, 2);
  assert.equal(started.length, 6);
});
```

- [ ] **Step 2: Run the preload test and verify RED**

Run: `node --test tests/threatlockerPreload.test.ts`

Expected: FAIL because `preload.ts` does not exist.

- [ ] **Step 3: Implement the bounded scheduler and coordinator**

`runThreatLockerPreload` runs the ordered loaders through two workers and uses
`Promise.allSettled` semantics per task. `ThreatLockerPreloader` calls it
immediately and every 60 seconds with the exact cache keys already consumed by
the page:

```ts
const THREATLOCKER_PRELOAD_MS = 60_000;
const keys = {
  apps: "threatlocker:global:apps",
  devices: "threatlocker:global:devices",
  policies: "threatlocker:global:policies",
  approvals: "threatlocker:global:approvals",
  cleanupOperations: "threatlocker:global:cleanup-operations",
  cleanupCandidates: "threatlocker:global:cleanup-candidates",
} as const;
```

The coordinator uses non-forced loads on the first run and forced refreshes on
the interval. It never renders UI and clears its timer on unmount.

- [ ] **Step 4: Mount preload and clear on logout**

Mount `<ThreatLockerPreloader />` inside `AuthedProviders`, after auth has
completed and outside the route outlet. Call
`clearSessionQueries("threatlocker:")` in `logout` and in failed session
restoration before setting status to anonymous.

- [ ] **Step 5: Reuse shared keys in the page and cleanup tab**

Export the key constants from `preload.ts` and replace string literals in
`ThreatLockerPage.tsx` and `CleanupTab.tsx`. Existing hooks then join preload
requests and render already-loaded results immediately.

- [ ] **Step 6: Run frontend tests and build**

Run: `npm test && npm run build`

Expected: all query-store, preload, cleanup, and lifecycle tests PASS.

- [ ] **Step 7: Commit the preload coordinator**

```bash
git add frontend/src/App.tsx frontend/src/store/auth.tsx frontend/src/features/threatlocker/preload.ts frontend/src/features/threatlocker/ThreatLockerPreloader.tsx frontend/src/features/threatlocker/ThreatLockerPage.tsx frontend/src/features/threatlocker/CleanupTab.tsx frontend/tests/threatlockerPreload.test.ts
git commit -m "feat: preload ThreatLocker session data"
```

### Task 3: Shared backend application inventory

**Files:**
- Create: `backend/internal/server/threatlocker_snapshot.go`
- Modify: `backend/internal/server/server.go`
- Modify: `backend/internal/server/threatlocker.go`
- Modify: `backend/internal/server/server_tl_test.go`

**Interfaces:**
- Produces: `func (s *Server) tlApplicationInventory(ctx context.Context, force bool) ([]model.TLApplication, error)`
- Consumes: `threatlocker.Provider.Applications` and the existing global application search request.
- Preserves: `GET /api/v1/threatlocker/apps` and `GET /api/v1/threatlocker/apps/cleanup-candidates`.

- [ ] **Step 1: Add failing endpoint tests**

Extend the fake portal with a per-path request count. Test that an Apps request
followed by cleanup candidates makes one
`Application/ApplicationGetByParameters` inventory sequence, concurrent
requests join one sequence, `?refresh=true` causes another sequence, and a
failed first request is retried rather than cached:

```go
func TestThreatLockerAppsAndCleanupCandidatesShareInventory(t *testing.T) {
  // Configure applications spanning two organizations.
  // GET /threatlocker/apps, then GET /threatlocker/apps/cleanup-candidates.
  // Assert both are 200 and the portal inventory page was requested once.
}

func TestThreatLockerAppInventoryForceRefreshBypassesSnapshot(t *testing.T) {
  // GET apps twice, second with ?refresh=true.
  // Assert the portal inventory page was requested twice.
}
```

- [ ] **Step 2: Run focused backend tests and verify RED**

Run:

```bash
go test ./internal/server -run 'ThreatLocker(AppsAndCleanupCandidatesShareInventory|AppInventoryForceRefresh)' -count=1
```

Expected: FAIL because both routes independently call the portal and refresh
does not invalidate a snapshot.

- [ ] **Step 3: Implement the 60-second snapshot**

Add server fields for snapshot data, expiry, mutex, and
`singleflight.Group`. `tlApplicationInventory` returns a defensive slice copy
when current, otherwise joins one portal load. With `force=true`, invalidate
before entering the same flight key. Cache only successful results:

```go
const threatLockerInventoryTTL = 60 * time.Second

func (s *Server) tlApplicationInventory(
  ctx context.Context,
  force bool,
) ([]model.TLApplication, error)
```

Promote `golang.org/x/sync` from indirect to direct in `backend/go.mod` because
the server imports `singleflight`.

- [ ] **Step 4: Route Apps and cleanup candidates through the snapshot**

Use the shared inventory only for the unfiltered global Apps request and the
cleanup-candidate endpoint. Preserve filtered Apps search as a direct portal
query. Parse `refresh=true` on both endpoints. Move candidate ranking to a
helper that accepts the already-loaded application slice so it has no portal
side effects.

- [ ] **Step 5: Run backend checks**

Run:

```bash
go test ./internal/server -run ThreatLocker -count=1
make vet test build
```

Expected: all focused and repository backend checks PASS.

- [ ] **Step 6: Commit the backend snapshot**

```bash
git add backend/go.mod backend/internal/server/server.go backend/internal/server/threatlocker.go backend/internal/server/threatlocker_snapshot.go backend/internal/server/server_tl_test.go
git commit -m "perf: share ThreatLocker application inventory"
```

### Task 4: Manual refresh, documentation, and full acceptance

**Files:**
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/features/threatlocker/ThreatLockerPage.tsx`
- Modify: `frontend/src/features/threatlocker/CleanupTab.tsx`
- Modify: `RTM ThreatLocker Module.md`
- Modify: `RTM API Specification.md`

**Interfaces:**
- Consumes: `refresh=true` from Task 3 and forced session-query loads from Task 1.
- Produces: manual refresh that bypasses both cache layers.

- [ ] **Step 1: Add a client URL test**

Add a pure URL builder test proving forced Apps and cleanup-candidate reads add
`refresh=true` while ordinary reads retain their existing paths. Extract:

```ts
export function threatLockerReadPath(
  suffix: string,
  options: { refresh?: boolean } = {},
): string
```

- [ ] **Step 2: Run the client URL test and verify RED**

Run: `node --test tests/threatlockerPreload.test.ts`

Expected: FAIL because `threatLockerReadPath` does not yet support refresh.

- [ ] **Step 3: Wire manual refresh through both layers**

Allow `api.threatlocker.apps` and `appCleanupCandidates` to accept
`{ refresh?: boolean }`. The toolbar Refresh action calls forced loaders with
the backend refresh option; timer-driven refresh remains a normal shared
snapshot read.

- [ ] **Step 4: Update module and API documentation**

Document the session-only preload, 60-second refresh, application snapshot,
`refresh=true`, error behavior, and the fact that write/verification endpoints
are never cached.

- [ ] **Step 5: Run all local verification**

Run:

```bash
cd backend && make vet test build
cd ../frontend && npm test && npm run build
git diff --check
```

Expected: all commands PASS.

- [ ] **Step 6: Deploy only RTM to demo**

Inspect the shared host, preserve `.env` and `secrets/`, sync with strict SSH,
and run:

```bash
cd /home/campbellservers/rtm-demo &&
docker compose -p rtm -f docker-compose.demo.yml up --build -d
```

If the strict SSH key or known-hosts file is unavailable, stop and report that
deployment boundary without weakening host verification.

- [ ] **Step 7: Verify authenticated live behavior**

After a fresh login, inspect network timing and RTM-only logs. Prove:

- ThreatLocker requests begin while another authenticated route is visible;
- opening ThreatLocker uses the completed current-session values;
- cleanup candidates do not trigger a second full application portal fetch;
- manual Refresh causes a new portal inventory fetch;
- Nginx accepts the configured 120-second proxy limits;
- all four RTM containers remain healthy; and
- no ThreatLocker write endpoint was invoked.

- [ ] **Step 8: Commit the integration task**

```bash
git add frontend/src/api/client.ts frontend/src/features/threatlocker/ThreatLockerPage.tsx frontend/src/features/threatlocker/CleanupTab.tsx frontend/tests/threatlockerPreload.test.ts 'RTM ThreatLocker Module.md' 'RTM API Specification.md'
git commit -m "docs: document ThreatLocker session preload"
```
