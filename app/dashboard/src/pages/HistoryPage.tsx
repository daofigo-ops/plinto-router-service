import type { HistoryItem } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';
import { EmptyState } from '../components/EmptyState';

interface Props {
  history: HistoryItem[];
}

export function HistoryPage({ history }: Props) {
  if (!history.length) {
    return <EmptyState title="No scan history yet" body="Run scans with history enabled to create timestamped report folders." />;
  }

  return (
    <div className="stack">
      <section className="page-title">
        <p className="eyebrow">Scan archive</p>
        <h1>History</h1>
        <p className="muted">Reads from reports/scans and summarizes each timestamped scan run.</p>
      </section>
      <div className="history-list">
        {history.map((item) => (
          <article className="history-card" key={item.id}>
            <div>
              <h3>{item.id}</h3>
              <p className="muted">{item.path}</p>
            </div>
            <div className="history-stats">
              <span>{item.finding_count} findings</span>
              {item.summary ? <RiskBadge level={item.summary.highest_risk_level} score={item.summary.highest_risk_score} /> : null}
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
