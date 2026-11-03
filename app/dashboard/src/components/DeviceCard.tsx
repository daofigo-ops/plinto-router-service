import type { Finding } from '../api/client';
import { RiskBadge } from './RiskBadge';

interface Props {
  ip: string;
  findings: Finding[];
}

export function DeviceCard({ ip, findings }: Props) {
  const maxRisk = findings.reduce((max, item) => Math.max(max, item.risk_score || 0), 0);
  const top = findings.find((item) => item.risk_score === maxRisk) || findings[0];

  return (
    <article className="device-card">
      <div className="device-head">
        <div>
          <p className="eyebrow">Host</p>
          <h3>{ip}</h3>
        </div>
        <RiskBadge level={top?.risk_level || 'Low'} score={maxRisk} />
      </div>
      <div className="service-list">
        {findings.map((item) => (
          <div className="service-row" key={`${item.ip}:${item.port}:${item.scheme}`}>
            <div>
              <strong>{item.port} / {item.scheme.toUpperCase()}</strong>
              <span>{item.device_type} · {item.vendor_guess}</span>
              <small>{item.title || item.server || item.redirect_location || 'No title/server banner'}</small>
            </div>
            <div className="service-side">
              <RiskBadge level={item.risk_level} score={item.risk_score} />
              <small>{item.dns_audit?.status || 'DNS not checked'}</small>
            </div>
          </div>
        ))}
      </div>
    </article>
  );
}
