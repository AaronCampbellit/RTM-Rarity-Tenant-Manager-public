/**
 * Minimal async-data hook. Returns { data, loading, error } so every screen
 * can render explicit loading / empty / error / success states as required by
 * the UX + coding specs. (Swappable for TanStack Query later without changing
 * call sites much.)
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { RtmApiError } from "./client";
import {
  loadSessionQuery,
  readSessionQuery,
  subscribeSessionQuery,
} from "./sessionQueryStore";

export interface AsyncState<T> {
  data: T | undefined;
  loading: boolean;
  refreshing?: boolean;
  error: RtmApiError | Error | undefined;
}

export function useAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[] = [],
  options: { enabled?: boolean } = {},
): AsyncState<T> {
  const enabled = options.enabled !== false;
  const [state, setState] = useState<AsyncState<T>>({
    data: undefined,
    loading: enabled,
    error: undefined,
  });

  useEffect(() => {
    let alive = true;
    if (!enabled) {
      setState({ data: undefined, loading: false, error: undefined });
      return () => { alive = false; };
    }
    setState({ data: undefined, loading: true, error: undefined });
    fn()
      .then((data) => alive && setState({ data, loading: false, error: undefined }))
      .catch(
        (error) =>
          alive && setState({ data: undefined, loading: false, error }),
      );
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled]);

  return state;
}

export interface RefreshingAsyncState<T> extends AsyncState<T> {
  refresh: () => void;
}

let anonymousQuerySequence = 0;

export function useRefreshingAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[] = [],
  options: { intervalMs?: number; cacheKey?: string; enabled?: boolean; failureTtlMs?: number } = {},
): RefreshingAsyncState<T> {
  const enabled = options.enabled !== false;
  const anonymousKey = useRef<string>();
  if (!anonymousKey.current) anonymousKey.current = `async:${++anonymousQuerySequence}`;
  const cacheKey = options.cacheKey ?? anonymousKey.current;
  const initial = readSessionQuery<T>(cacheKey);
  const [state, setState] = useState<AsyncState<T>>({
    data: initial.data,
    loading: initial.data === undefined,
    refreshing: initial.refreshing,
    error: initial.error,
  });
  const [refreshKey, setRefreshKey] = useState(0);
  const fnRef = useRef(fn);
  const previousEffectKey = useRef<string>();
  fnRef.current = fn;

  const refresh = useCallback(() => {
    setRefreshKey((x) => x + 1);
  }, []);

  useEffect(() => {
    if (!enabled) {
      setState({ data: undefined, loading: false, refreshing: false, error: undefined });
      return;
    }
    const update = () => {
      const snapshot = readSessionQuery<T>(cacheKey);
      setState({
        data: snapshot.data,
        loading: snapshot.loading || (snapshot.data === undefined && snapshot.error === undefined),
        refreshing: snapshot.refreshing,
        error: snapshot.error,
      });
    };
    const unsubscribe = subscribeSessionQuery(cacheKey, update);
    update();
    const force = previousEffectKey.current === cacheKey;
    previousEffectKey.current = cacheKey;
    void loadSessionQuery(cacheKey, () => fnRef.current(), { force, failureTtlMs: options.failureTtlMs }).catch(() => undefined);
    return unsubscribe;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, refreshKey, cacheKey, enabled, options.failureTtlMs]);

  useEffect(() => {
    if (!enabled || !options.intervalMs) return;
    const timer = window.setInterval(refresh, options.intervalMs);
    return () => window.clearInterval(timer);
  }, [enabled, options.intervalMs, refresh]);

  return { ...state, refresh };
}
