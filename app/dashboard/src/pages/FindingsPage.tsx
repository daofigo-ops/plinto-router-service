import type { LatestReport } from '../api/client';
import { RiskBadge } from '../components/RiskBadge';
import { EmptyState } from '../components/EmptyState';

interface Props {
  report: LatestReport | null;
}

export function FindingsPage({ report }: Props) {
  const findings = [...(report?.findings || [])].sort((a, b) => b.risk_score - a.risk_score);
  if (!findings.length) {
    return <EmptyState title="No findings yet" body="Run a scan to create findings and recommendations." />;
  }

  return (
    <div className="stack">
      <section className="page-title">
        <p className="eyebrow">Finding detail</p>
        <h1>Risk and recommendations</h1>
      </section>
      <div className="findings-list">
        {findings.map((item) => (
          <article className="finding-card" key={`${item.ip}:${item.port}:${item.scheme}`}>
            <div className="finding-head">
              <div>
                <h3>{item.ip}:{item.port} <span>{item.scheme.toUpperCase()}</span></h3>
                <p>{item.device_type} · {item.vendor_guess}</p>
              </div>
              <RiskBadge level={item.risk_level} score={item.risk_score} />
            </div>
            <div className="finding-columns">
              <div>
                <strong>Evidence</strong>
                <ul>{(item.evidence.length ? item.evidence : ['No strong evidence captured']).map((v, i) => <li key={i}>{v}</li>)}</ul>
              </div>
              <div>
                <strong>Risk reasons</strong>
                <ul>{(item.risk_reasons.length ? item.risk_reasons : ['No major risk reason assigned']).map((v, i) => <li key={i}>{v}</li>)}</ul>
              </div>
              <div>
                <strong>Recommendations</strong>
                <ul>{(item.recommendations.length ? item.recommendations : ['No recommendation generated']).map((v, i) => <li key={i}>{v}</li>)}</ul>
              </div>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
