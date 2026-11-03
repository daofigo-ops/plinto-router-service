import { useCallback, useEffect, useState } from 'react';
import { Activity, FileText, History, LayoutDashboard, ListChecks, PlayCircle, ShieldCheck, Server } from 'lucide-react';
import { apiGet, type HistoryItem, type LatestReport } from './api/client';
import { DashboardPage } from './pages/DashboardPage';
import { DevicesPage } from './pages/DevicesPage';
import { FindingsPage } from './pages/FindingsPage';
import { HistoryPage } from './pages/HistoryPage';
import { PentestLogPage } from './pages/PentestLogPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScanPage } from './pages/ScanPage';

type Page = 'dashboard' | 'devices' | 'findings' | 'scan' | 'history' | 'reports' | 'pentest';

const nav = [
  { id: 'dashboard' as Page, label: 'Overview', icon: LayoutDashboard },
  { id: 'devices' as Page, label: 'Devices', icon: Server },
  { id: 'findings' as Page, label: 'Findings', icon: ListChecks },
  { id: 'scan' as Page, label: 'Run Scan', icon: PlayCircle },
  { id: 'history' as Page, label: 'History', icon: History },
  { id: 'reports' as Page, label: 'Reports', icon: FileText },
  { id: 'pentest' as Page, label: 'Pentest Log', icon: ShieldCheck },
];

function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [report, setReport] = useState<LatestReport | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [pentestLog, setPentestLog] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [latest, historyResponse, logResponse] = await Promise.all([
        apiGet<LatestReport>('/api/latest'),
        apiGet<{ count: number; items: HistoryItem[] }>('/api/history'),
        apiGet<{ count: number; items: Array<Record<string, unknown>> }>('/api/pentest/log'),
      ]);
      setReport(latest);
      setHistory(historyResponse.items || []);
      setPentestLog(logResponse.items || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark"><Activity size={22} /></div>
          <div>
            <strong>Plinto</strong>
            <span>Network Audit</span>
          </div>
        </div>
        <nav>
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={page === item.id ? 'active' : ''} onClick={() => setPage(item.id)}>
                <Icon size={18} />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-note">
          <strong>Local-only console</strong>
          <span>API: 127.0.0.1:8787</span>
          <button onClick={() => void refresh()}>Refresh data</button>
        </div>
      </aside>

      <main className="main-area">
        {page === 'dashboard' ? <DashboardPage report={report} loading={loading} error={error} /> : null}
        {page === 'devices' ? <DevicesPage report={report} /> : null}
        {page === 'findings' ? <FindingsPage report={report} /> : null}
        {page === 'scan' ? <ScanPage onScanFinished={refresh} /> : null}
        {page === 'history' ? <HistoryPage history={history} /> : null}
        {page === 'reports' ? <ReportsPage /> : null}
        {page === 'pentest' ? <PentestLogPage items={pentestLog} /> : null}
      </main>
    </div>
  );
}

export default App;
