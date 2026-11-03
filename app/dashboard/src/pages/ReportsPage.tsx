import { reportUrl } from '../api/client';

export function ReportsPage() {
  return (
    <div className="stack">
      <section className="page-title">
        <p className="eyebrow">Exports</p>
        <h1>Latest reports</h1>
        <p className="muted">Open or download the latest generated reports. For older reports, use the History page.</p>
      </section>
      <section className="report-grid">
        <a className="report-card" href={reportUrl('html')} target="_blank">
          <span>HTML</span>
          <strong>Open visual report</strong>
          <small>Best for human review and print preview.</small>
        </a>
        <a className="report-card" href={reportUrl('json')} target="_blank">
          <span>JSON</span>
          <strong>Download machine report</strong>
          <small>Best for integrations, debugging, and diffing.</small>
        </a>
        <a className="report-card" href={reportUrl('csv')} target="_blank">
          <span>CSV</span>
          <strong>Download spreadsheet report</strong>
          <small>Best for Excel, LibreOffice, and client trackers.</small>
        </a>
      </section>
    </div>
  );
}
