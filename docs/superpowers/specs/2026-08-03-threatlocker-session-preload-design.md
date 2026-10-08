# ThreatLocker Session Preload Design

## Goal

Make the ThreatLocker page and cleanup analysis feel ready when an authenticated
operator opens them, without serving a snapshot from an earlier login session.

## Current Behavior

ThreatLocker data begins loading only after the route mounts. The page starts
independent requests for devices, approvals, policies, and applications. The
cleanup tab then starts another full application inventory request to compute
recommendations. Live inventories are large enough that these calls take
roughly 10 to 30 seconds, so route navigation exposes the full portal latency.

## Design

### Authenticated preload coordinator

Mount a headless ThreatLocker preload coordinator under the authenticated
application providers. After authentication and any required password rotation,
it begins loading the parent workspace without blocking navigation.

The coordinator prioritizes the large application and device inventories, then
loads policies, pending approvals, cleanup operations, and cleanup candidates.
At most two portal-heavy requests run concurrently so background work does not
overload ThreatLocker or delay ordinary RTM requests.

### Session-scoped query store

Replace the private hook-only map with a small ThreatLocker query store that:

- stores successful values only in browser memory;
- deduplicates callers by sharing an in-flight promise per query;
- exposes subscribe, refresh, and invalidate operations to hooks;
- records fetch time and quietly refreshes values every 60 seconds;
- never writes ThreatLocker inventory to local storage; and
- clears all values and pending references when authentication ends.

The ThreatLocker page reads this same store. If preload has completed, it
renders immediately. If a refresh is active, existing rows remain visible with
a non-blocking refreshing state. Manual Refresh invalidates the relevant
entries and requires a fresh portal read.

### Shared application snapshot for analysis

The backend will share the current application inventory between the
applications route and cleanup-candidate calculation for no more than 60
seconds. Concurrent callers join the same in-flight portal request. The
cleanup-candidate endpoint derives its ranking from that shared inventory
instead of downloading the full application library again.

A forced refresh invalidates the shared inventory before loading. The cache is
strictly an optimization: failed portal calls are not cached, and successful
responses retain the same API shapes and authorization checks.

### Cleanup analysis

Cleanup recommendations and the operation ledger begin loading during the
authenticated preload. Opening the Clean up tab consumes the session values
immediately and continues the normal 60-second background refresh. The guided
What-If, execute, and verification calls remain live operations and are never
answered from the inventory cache.

## Authentication and Error Handling

- Preload does not run for anonymous users or during forced password rotation.
- `NOT_CONNECTED` is retained and displayed by the ThreatLocker page; preload
  failures do not affect login or other RTM routes.
- Logout clears the ThreatLocker query store before the next operator can
  authenticate.
- A failed background refresh preserves the last successful current-session
  value and surfaces the error on the ThreatLocker page.
- Abandoned components do not cancel shared work needed by another subscriber.

## Testing and Acceptance

Automated tests will prove:

- two consumers of one key produce only one network request;
- preload data is immediately available when the page mounts;
- logout clears all ThreatLocker session data;
- refresh replaces visible data without blanking it;
- cleanup candidates reuse the shared application snapshot;
- forced refresh bypasses that snapshot; and
- failed requests are not cached.

Local completion requires backend vet, tests, and builds plus frontend tests and
production build. Demo acceptance requires an RTM-scoped deployment, a fresh
authenticated login, evidence that preload starts before ThreatLocker
navigation, and evidence that the ThreatLocker and Clean up tabs render the
preloaded results without duplicate full application downloads.

## Out of Scope

- Persistent or cross-login ThreatLocker browser caching
- Scheduled server snapshots or database persistence
- Changes to cleanup write safety, verification, or approval tokens
- Broad redesign of the ThreatLocker page
