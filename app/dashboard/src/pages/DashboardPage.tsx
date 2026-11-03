import type { LatestReport } from '../api/client';
import { reportUrl } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';
import { StatCard } from '../components/StatCard';
import { EmptyState } from '../components/EmptyState';

interface Props {
  report: LatestReport | null;
  loading: boolean;
  error: string | null;
}

export function DashboardPage({ report, loading, error }: Props) {
  if (loading) return <div className="panel"><p>Loading latest scan...</p></div>;
  if (error) return <div className="panel error-box"><strong>API error</strong><p>{error}</p></div>;
  if (!report?.summary) {
    return <EmptyState title="No scan report yet" body="Run a scan from the Scan page or from the terminal to populate the dashboard." />;
  }

  const summary = report.summary;
  return (
    <div className="stack">
      <section className="hero-card">
        <div>
          <p className="eyebrow">Latest authorized private-network audit</p>
          <h1>Plinto Local Dashboard</h1>
          <p className="muted">Target: {summary.target} · Finished: {new Date(summary.finished_at).toLocaleString()}</p>
        </div>
        <RiskBadge level={summary.highest_risk_level} score={summary.highest_risk_score} />
      </section>

      <section className="stat-grid">
        <StatCard label="Unique hosts" value={summary.unique_hosts} />
        <StatCard label="Web services" value={summary.service_count} />
        <StatCard label="Router-like" value={summary.router_like_count} />
        <StatCard label="HTTP only" value={summary.http_only_count} />
        <StatCard label="Server errors" value={summary.server_error_count} />
        <StatCard label="DNS review" value={summary.dns_needs_review_count} />
        <StatCard label="Pentest attempts" value={summary.pentest_attempt_count} hint={`${summary.pentest_success_count} success`} />
        <StatCard label="Findings" value={report.finding_count || report.findings?.length || 0} />
      </section>

      <section className="two-col">
        <div className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">Action queue</p>
              <h2>Top recommended actions</h2>
            </div>
          </div>
          {summary.top_actions?.length ? (
            <ol className="action-list">
              {summary.top_actions.map((item, index) => <li key={index}>{item}</li>)}
            </ol>
          ) : <p className="muted">No top actions were generated for the latest scan.</p>}
        </div>

        <div className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">Reports</p>
              <h2>Latest exports</h2>
            </div>
          </div>
          <div className="button-row">
            <a className="button" href={reportUrl('html')} target="_blank">Open HTML</a>
            <a className="button secondary" href={reportUrl('json')} target="_blank">Download JSON</a>
            <a className="button secondary" href={reportUrl('csv')} target="_blank">Download CSV</a>
          </div>
          <p className="muted small">The dashboard never exposes passwords. Pentest attempts are shown as redacted audit entries only.</p>
        </div>
      </section>
    </div>
  );
}
