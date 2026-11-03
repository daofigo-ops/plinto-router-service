import { FormEvent, useState } from 'react';
import { apiPost, type RunScanPayload } from '../api/client';

interface RunResponse {
  ok: boolean;
  command: string[];
  started_at: string;
  finished_at: string;
  exit_code: number;
  stdout: string;
  stderr: string;
}

interface Props {
  onScanFinished: () => Promise<void>;
}

export function ScanPage({ onScanFinished }: Props) {
  const [mode, setMode] = useState<'local' | 'gateway' | 'custom'>('local');
  const [target, setTarget] = useState('192.168.1.0/24');
  const [ports, setPorts] = useState('80,443,8000,8080,8443');
  const [deepFingerprint, setDeepFingerprint] = useState(true);
  const [dnsAudit, setDnsAudit] = useState(true);
  const [saveHistory, setSaveHistory] = useState(true);
  const [updateInventory, setUpdateInventory] = useState(true);
  const [pentest, setPentest] = useState(false);
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const [applyPentest, setApplyPentest] = useState(false);
  const [checkDefaults, setCheckDefaults] = useState(false);
  const [credentialsFile, setCredentialsFile] = useState('config/credentials.yaml');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RunResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setRunning(true);
    setResult(null);
    setError(null);
    const payload: RunScanPayload = {
      mode,
      target: mode === 'custom' ? target : undefined,
      ports,
      report_format: 'all',
      deep_fingerprint: deepFingerprint,
      dns_audit: dnsAudit,
      save_history: saveHistory,
      update_inventory: updateInventory,
      pentest,
      ownership_confirmed: ownershipConfirmed,
      apply_pentest: applyPentest,
      check_defaults: checkDefaults,
      credentials_file: credentialsFile || undefined,
    };

    try {
      const response = await apiPost<RunResponse>('/api/scans/run', payload);
      setResult(response);
      await onScanFinished();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="stack">
      <section className="page-title">
        <p className="eyebrow">Controlled execution</p>
        <h1>Run scan</h1>
        <p className="muted">Launches the same CLI scanner through the local API. Public-IP scanning and unsafe pentest actions remain blocked by backend guards.</p>
      </section>

      <form className="scan-form" onSubmit={submit}>
        <div className="form-section">
          <h3>Target</h3>
          <div className="segmented">
            <button type="button" className={mode === 'local' ? 'active' : ''} onClick={() => setMode('local')}>Local LAN</button>
            <button type="button" className={mode === 'gateway' ? 'active' : ''} onClick={() => setMode('gateway')}>Gateway only</button>
            <button type="button" className={mode === 'custom' ? 'active' : ''} onClick={() => setMode('custom')}>Custom</button>
          </div>
          {mode === 'custom' ? (
            <label>
              Target IP/CIDR
              <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.1.1 or 192.168.1.0/24" />
            </label>
          ) : null}
          <label>
            Ports
            <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="80,443,8000,8080,8443" />
          </label>
        </div>

        <div className="form-section grid2">
          <label className="check"><input type="checkbox" checked={deepFingerprint} onChange={(e) => setDeepFingerprint(e.target.checked)} /> Deep fingerprinting</label>
          <label className="check"><input type="checkbox" checked={dnsAudit} onChange={(e) => setDnsAudit(e.target.checked)} /> DNS audit</label>
          <label className="check"><input type="checkbox" checked={saveHistory} onChange={(e) => setSaveHistory(e.target.checked)} /> Save history</label>
          <label className="check"><input type="checkbox" checked={updateInventory} onChange={(e) => setUpdateInventory(e.target.checked)} /> Update inventory</label>
        </div>

        <div className="form-section pentest-box">
          <h3>Restricted Pentest Mode</h3>
          <p className="muted small">Use only on your own or explicitly authorized network. Validation is rate-limited and logged.</p>
          <label className="check"><input type="checkbox" checked={pentest} onChange={(e) => setPentest(e.target.checked)} /> Enable Pentest Mode</label>
          {pentest ? (
            <div className="pentest-controls">
              <label className="check"><input type="checkbox" checked={ownershipConfirmed} onChange={(e) => setOwnershipConfirmed(e.target.checked)} /> I own or am authorized to test this network</label>
              <label className="check"><input type="checkbox" checked={applyPentest} onChange={(e) => setApplyPentest(e.target.checked)} /> Apply credential validation attempts</label>
              <label className="check"><input type="checkbox" checked={checkDefaults} onChange={(e) => setCheckDefaults(e.target.checked)} /> Check tiny default-credential list if enabled in config</label>
              <label>
                Credentials YAML
                <input value={credentialsFile} onChange={(e) => setCredentialsFile(e.target.value)} placeholder="config/credentials.yaml" />
              </label>
            </div>
          ) : null}
        </div>

        <button className="button run-button" type="submit" disabled={running}>{running ? 'Running scan...' : 'Run scan'}</button>
      </form>

      {error ? <div className="panel error-box"><strong>Scan failed</strong><pre>{error}</pre></div> : null}
      {result ? (
        <div className={`panel ${result.ok ? '' : 'error-box'}`}>
          <h2>Run result</h2>
          <p><strong>Exit:</strong> {result.exit_code} · <strong>Command:</strong> {result.command.join(' ')}</p>
          <div className="terminal-output">
            <h3>stdout</h3>
            <pre>{result.stdout || '-'}</pre>
            <h3>stderr</h3>
            <pre>{result.stderr || '-'}</pre>
          </div>
        </div>
      ) : null}
    </div>
  );
}
