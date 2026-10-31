import { useCallback, useEffect, useState } from "react";
import { AppShell, type View } from "./components/AppShell";
import { Overview } from "./pages/Overview";
import { Scanner } from "./pages/Scanner";
import { Result } from "./pages/Result";
import { History } from "./pages/History";
import { analyze } from "./engine/analyze";
import { useHistory, useSettings } from "./lib/store";
import type { ScanResult, ScanType } from "./types";

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [active, setActive] = useState<ScanResult | null>(null);

  const { settings, update } = useSettings();
  const { history, add, remove, clear } = useHistory(settings.storeHistory);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, [view, active?.id]);

  const navigate = useCallback((next: View) => {
    setView(next);
    if (next !== "result") setActive(null);
  }, []);

  const runScan = useCallback(
    (input: string, type: ScanType) => {
      const result = analyze(input, type, { sensitivity: settings.sensitivity });
      add(result);
      setActive(result);
      setView("result");
    },
    [add, settings.sensitivity],
  );

  const openScan = useCallback((scan: ScanResult) => {
    setActive(scan);
    setView("result");
  }, []);

  const deleteScan = useCallback(
    (id: string) => {
      remove(id);
      setActive(null);
      setView("history");
    },
    [remove],
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
