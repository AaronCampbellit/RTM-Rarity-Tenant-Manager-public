export interface SessionQuerySnapshot<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  refreshing: boolean;
}

interface SessionQueryEntry {
  data?: unknown;
  error?: Error;
  inFlight?: Promise<unknown>;
  retryAfter?: number;
  listeners: Set<() => void>;
}

const entries = new Map<string, SessionQueryEntry>();
let generation = 0;

function entryFor(key: string): SessionQueryEntry {
  let entry = entries.get(key);
  if (!entry) {
    entry = { listeners: new Set() };
    entries.set(key, entry);
  }
  return entry;
}

function publish(entry: SessionQueryEntry) {
  for (const listener of entry.listeners) listener();
}

export function readSessionQuery<T>(key: string): SessionQuerySnapshot<T> {
  const entry = entries.get(key);
  const inFlight = entry?.inFlight !== undefined;
  const hasData = entry?.data !== undefined;
  return {
    data: entry?.data as T | undefined,
    error: entry?.error,
    loading: inFlight && !hasData,
    refreshing: inFlight && hasData,
  };
}

export function subscribeSessionQuery(key: string, listener: () => void): () => void {
  const entry = entryFor(key);
  entry.listeners.add(listener);
  return () => entry.listeners.delete(listener);
}

export function loadSessionQuery<T>(
  key: string,
  loader: () => Promise<T>,
  options: { force?: boolean; failureTtlMs?: number } = {},
): Promise<T> {
  const entry = entryFor(key);
  if (entry.inFlight) return entry.inFlight as Promise<T>;
  if (!options.force && entry.data !== undefined) {
    return Promise.resolve(entry.data as T);
  }
  if (!options.force && entry.error && (entry.retryAfter ?? 0) > Date.now()) {
    return Promise.reject(entry.error);
  }

  const requestGeneration = generation;
  const request = loader();
  entry.inFlight = request;
  publish(entry);
  request.then(
    (data) => {
      if (requestGeneration !== generation || entries.get(key) !== entry) return;
      entry.data = data;
      entry.error = undefined;
      entry.retryAfter = undefined;
      entry.inFlight = undefined;
      publish(entry);
    },
    (error: unknown) => {
      if (requestGeneration !== generation || entries.get(key) !== entry) return;
      entry.error = error instanceof Error ? error : new Error(String(error));
      entry.retryAfter = options.failureTtlMs ? Date.now() + options.failureTtlMs : undefined;
      entry.inFlight = undefined;
      publish(entry);
    },
  );
  return request;
}

export function clearSessionQueries(prefix = "") {
  generation += 1;
  for (const key of entries.keys()) {
    if (!prefix || key.startsWith(prefix)) entries.delete(key);
  }
}
