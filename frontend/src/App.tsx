import { useCallback, useEffect, useState } from "react";
import { AppShell, type View } from "./components/AppShell";
import { Overview } from "./pages/Overview";
import { Scanner } from "./pages/Scanner";
import { Result } from "./pages/Result";
import { History } from "./pages/History";
import { analyzeInput } from "./lib/api";
import { useHistory, useSettings } from "./lib/store";
import type { ScanResult, ScanType } from "./types";

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [active, setActive] = useState<ScanResult | null>(null);

  const { settings, update } = useSettings();
  const { history, add, remove, clear } = useHistory(settings.storeHistory);

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  }, [view, active?.id]);

  // Synchronize dark/light theme on document root
  useEffect(() => {
    const theme = settings.theme || "light";
    document.documentElement.setAttribute("data-theme", theme);
    if (theme === "light") {
      document.documentElement.classList.add("light");
      document.documentElement.classList.remove("dark");
    } else {
      document.documentElement.classList.add("dark");
      document.documentElement.classList.remove("light");
    }
  }, [settings.theme]);

  const navigate = useCallback((next: View) => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    setView(next);
    if (next !== "result") setActive(null);
  }, []);

  const runScan = useCallback(
    async (input: string, type: ScanType) => {
      const mode = type === "url" ? "url" : "message";
      const apiRes = await analyzeInput(input, mode);

      const scan: ScanResult = {
        id: `scan-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        type,
        input,
        createdAt: Date.now(),
        score: apiRes.score,
        level: apiRes.verdict.level,
        verdict: apiRes.verdict.label,
        advice: apiRes.verdict.advice,
        reasons: apiRes.reasons || [],
        host: apiRes.host,
        urls: apiRes.urls,
        note: apiRes.note,
        redirectChain: apiRes.redirectChain,
        finalUrl: apiRes.finalUrl,
        threatIntel: apiRes.threatIntel,
        ai: apiRes.ai,
        aiOpinion: apiRes.ai,
        assessment: apiRes.assessment ?? null,
      };

      add(scan);
      setActive(scan);
      setView("result");
    },
    [add],
  );

  const openScan = useCallback((scan: ScanResult) => {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    setActive(scan);
    setView("result");
  }, []);

  const deleteScan = useCallback(
    (id: string) => {
      window.scrollTo({ top: 0, left: 0, behavior: "instant" });
      remove(id);
      setActive(null);
      setView(history.length <= 1 ? "scan" : "history");
    },
    [remove, history.length],
  );

  return (
    <AppShell
      view={view}
      onNavigate={navigate}
      settings={settings}
      onUpdateSettings={update}
      onClearHistory={clear}
      historyCount={history.length}
    >
      {view === "overview" && (
        <Overview history={history} onNavigate={navigate} onOpenScan={openScan} />
      )}

      {view === "scan" && <Scanner onAnalyse={runScan} />}

      {view === "result" && active && (
        <Result scan={active} onNewScan={() => navigate("scan")} onDelete={deleteScan} />
      )}

      {view === "result" && !active && <Scanner onAnalyse={runScan} />}

      {view === "history" && (
        <History
          history={history}
          onOpenScan={openScan}
          onNewScan={() => navigate("scan")}
          onClear={clear}
        />
      )}
    </AppShell>
  );
}
