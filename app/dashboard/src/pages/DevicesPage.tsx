import type { Finding, LatestReport } from '../api/client';
import { DeviceCard } from '../components/DeviceCard';
import { EmptyState } from '../components/EmptyState';

interface Props {
  report: LatestReport | null;
}

function groupByIp(findings: Finding[]) {
  return findings.reduce<Record<string, Finding[]>>((acc, item) => {
    acc[item.ip] = acc[item.ip] || [];
    acc[item.ip].push(item);
    return acc;
  }, {});
}

export function DevicesPage({ report }: Props) {
  const findings = report?.findings || [];
  const grouped = groupByIp(findings);
  const ips = Object.keys(grouped).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

  if (!ips.length) {
    return <EmptyState title="No devices found yet" body="Run a scan to populate grouped device and service cards." />;
  }

  return (
    <div className="stack">
      <section className="page-title">
        <p className="eyebrow">Inventory view</p>
        <h1>Devices and services</h1>
        <p className="muted">Grouped by host, with service classification, risk, DNS audit status, and top visible banners.</p>
      </section>
      <div className="device-grid">
        {ips.map((ip) => <DeviceCard key={ip} ip={ip} findings={grouped[ip]} />)}
      </div>
    </div>
  );
}
