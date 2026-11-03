import type { RiskLevel } from '../api/client';

interface Props {
  level?: RiskLevel;
  score?: number;
}

export function RiskBadge({ level = 'Low', score }: Props) {
  const cls = String(level).toLowerCase();
  return <span className={`risk-badge ${cls}`}>{level}{typeof score === 'number' ? ` · ${score}` : ''}</span>;
}
