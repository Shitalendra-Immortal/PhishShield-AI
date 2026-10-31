import { useCallback, useEffect, useState } from "react";
import type { ScanResult, Settings } from "../types";

const HISTORY_KEY = "phishshield.history.v1";
const SETTINGS_KEY = "phishshield.settings.v1";
const MAX_HISTORY = 100;

function read<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? ({ ...fallback, ...JSON.parse(raw) } as T) : fallback;
  } catch {
    return fallback;
  }
}

function readList<T>(key: string): T[] {
  try {
    const raw = window.localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

function write(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable — history simply becomes session-only */
  }
}

export const DEFAULT_SETTINGS: Settings = { sensitivity: "balanced", storeHistory: true };

export function useSettings() {
  const [settings, setSettings] = useState<Settings>(() => read(SETTINGS_KEY, DEFAULT_SETTINGS));

  useEffect(() => {
    write(SETTINGS_KEY, settings);
  }, [settings]);

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => ({ ...prev, ...patch }));
  }, []);

  return { settings, update };
}

export function useHistory(enabled: boolean) {
  const [history, setHistory] = useState<ScanResult[]>(() => readList<ScanResult>(HISTORY_KEY));

  // Turning history off must also remove anything already written to this device.
  useEffect(() => {
    if (!enabled) write(HISTORY_KEY, []);
  }, [enabled]);

  const persist = useCallback(
    (next: ScanResult[]) => {
      setHistory(next);
      if (enabled) write(HISTORY_KEY, next);
      else write(HISTORY_KEY, []);
    },
    [enabled],
  );

  const add = useCallback(
    (scan: ScanResult) => {
      setHistory((prev) => {
        const next = [scan, ...prev].slice(0, MAX_HISTORY);
        if (enabled) write(HISTORY_KEY, next);
        return next;
      });
    },
    [enabled],
  );

  const remove = useCallback(
    (id: string) => {
      setHistory((prev) => {
        const next = prev.filter((s) => s.id !== id);
        if (enabled) write(HISTORY_KEY, next);
        return next;
      });
    },
    [enabled],
  );

  const clear = useCallback(() => persist([]), [persist]);

  return { history, add, remove, clear };
}

export const stats = (history: ScanResult[]) => ({
  total: history.length,
  threats: history.filter((s) => s.level === "high").length,
  suspicious: history.filter((s) => s.level === "suspicious").length,
  safe: history.filter((s) => s.level === "low").length,
});
