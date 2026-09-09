import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { lookupRaw, computeDRS, drsClass } from '../api/cveApi.js';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LineChart, Line, CartesianGrid,
} from 'recharts';

const RISK_COLOR = {
  critical: '#FF3131',
  high:     '#FFB800',
  medium:   '#F4E409',
  low:      '#00FF41',
};

const SEVERITY_DATA = [
  { label: 'CRITICAL', key: 'critical', color: '#FF3131' },
  { label: 'HIGH',     key: 'high',     color: '#FFB800' },
  { label: 'MEDIUM',   key: 'medium',   color: '#F4E409' },
  { label: 'LOW',      key: 'low',      color: '#00FF41' },
];

const CVSS_RANGES = [
  { name: '0–2',  min: 0,  max: 2 },
  { name: '2–4',  min: 2,  max: 4 },
  { name: '4–6',  min: 4,  max: 6 },
  { name: '6–8',  min: 6,  max: 8 },
  { name: '8–10', min: 8,  max: 10 },
];

const CUSTOM_TOOLTIP_STYLE = {
  background: '#0c130e',
  border: '1px solid #00FF41',
  fontFamily: 'JetBrains Mono, monospace',
  fontSize: 11,
  color: '#e2ffe8',
  padding: '6px 10px',
};

function SectionBox({ title, children, style }) {
  return (
    <div className="terminal-box" style={{ padding: 'var(--sp-5)', paddingTop: 'var(--sp-6)', ...style }}>
      <div className="terminal-box-title">// {title}</div>
      {children}
    </div>
  );
}

export default function Analysis({ stats }) {
  const navigate = useNavigate();
  const [scanProduct, setScanProduct] = useState('pan-os');
  const [scanVersion, setScanVersion] = useState('8.1.20');
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState('');

  /* Severity pie data from global stats */
  const pieData = SEVERITY_DATA
    .map(s => ({ name: s.label, value: stats?.[s.key] || 0, color: s.color }))
    .filter(d => d.value > 0);

  /* CVSS distribution from scan results */
  const cvssDistData = scanResults?.results?.length
    ? CVSS_RANGES.map(r => ({
        name: r.name,
        count: scanResults.results.filter(x => {
          const v = parseFloat(x.cvss);
          return v >= r.min && v < r.max;
        }).length,
      }))
    : [];

  /* DRS scatter from scan results */
  const drsData = scanResults?.results?.map(r => ({
    cve: r.cve_id,
    cvss: parseFloat(r.cvss) || 0,
    drs: computeDRS(r.cvss, r.label, r.exploit),
    exploit: r.exploit,
    label: r.label,
  })) || [];

  async function handleScan(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await lookupRaw(scanProduct.trim(), scanVersion.trim());
      setScanResults(data);
    } catch (err) {
      setError(`ERROR: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">THREAT_ANALYSIS :: RISK_INTELLIGENCE</div>
          <div className="page-subtitle">Charts, distributions, and vulnerability patterns</div>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid-4" style={{ marginBottom: 'var(--sp-5)' }}>
        {SEVERITY_DATA.map(s => (
          <div key={s.key} style={{ border: `1px solid ${s.color}`, padding: 'var(--sp-3) var(--sp-4)', background: 'var(--surface)' }}>
            <div style={{ fontSize: 'var(--fs-xs)', color: s.color, fontWeight: 700, letterSpacing: '0.1em' }}>{s.label}</div>
            <div style={{ fontSize: 28, fontWeight: 700, color: s.color, textShadow: `0 0 12px ${s.color}` }}>
              {stats?.[s.key] ?? '—'}
            </div>
          </div>
        ))}
      </div>

      {/* Row 1: Severity donut + Scan form */}
      <div className="grid-2" style={{ marginBottom: 'var(--sp-4)' }}>
        <SectionBox title="SEVERITY_DISTRIBUTION">
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} stroke="var(--bg)" strokeWidth={2}
                      style={{ filter: `drop-shadow(0 0 4px ${entry.color})` }} />
                  ))}
                </Pie>
                <Tooltip contentStyle={CUSTOM_TOOLTIP_STYLE} />
                <Legend
                  formatter={v => <span style={{ color: 'var(--text-secondary)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>{v}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40, fontSize: 'var(--fs-sm)' }}>
              Loading dataset stats…
            </div>
          )}
        </SectionBox>

        <SectionBox title="SCAN_INTERFACE">
          <p style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', marginBottom: 12 }}>
            Run a targeted scan to populate CVSS distribution and DRS charts below.
          </p>
          <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label htmlFor="a-product" style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>PRODUCT:</label>
              <input id="a-product" className="terminal-input" value={scanProduct} onChange={e => setScanProduct(e.target.value)} placeholder="e.g. pan-os" />
            </div>
            <div>
              <label htmlFor="a-version" style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', display: 'block', marginBottom: 3 }}>VERSION:</label>
              <input id="a-version" className="terminal-input" value={scanVersion} onChange={e => setScanVersion(e.target.value)} placeholder="e.g. 8.1.20" />
            </div>
            <button id="analysis-scan-btn" type="submit" className="btn" disabled={loading}>
              {loading ? '[ SCANNING… ]' : '[ RUN_ANALYSIS ]'}
            </button>
          </form>
          {error && <div role="alert" style={{ marginTop: 8, color: 'var(--risk-critical)', fontSize: 'var(--fs-xs)' }}>{error}</div>}
          {scanResults && !error && (
            <div style={{ marginTop: 10, fontSize: 'var(--fs-xs)', color: 'var(--primary)' }}>
              ✓ {scanResults.results.length} CVEs loaded for {scanResults.product} {scanResults.version}
            </div>
          )}
        </SectionBox>
      </div>

      {/* Row 2: CVSS distribution bar chart */}
      <SectionBox title="CVSS_SCORE_DISTRIBUTION" style={{ marginBottom: 'var(--sp-4)' }}>
        {cvssDistData.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={cvssDistData} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
              <CartesianGrid strokeDasharray="2 4" stroke="var(--surface-border)" vertical={false} />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={CUSTOM_TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,255,65,0.05)' }} />
              <Bar dataKey="count" radius={0}>
                {cvssDistData.map((entry, i) => {
                  const colors = ['#00FF41', '#00FF41', '#F4E409', '#FFB800', '#FF3131'];
                  return <Cell key={i} fill={colors[i]} style={{ filter: `drop-shadow(0 0 4px ${colors[i]})` }} />;
                })}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40, fontSize: 'var(--fs-sm)' }}>
            Run a scan above to see CVSS distribution
          </div>
        )}
      </SectionBox>

      {/* Row 3: DRS scores line chart */}
      {drsData.length > 0 && (
        <SectionBox title="DRS_SCORE_OVERVIEW" style={{ marginBottom: 'var(--sp-4)' }}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={drsData} margin={{ top: 5, right: 10, bottom: 30, left: 0 }}>
              <CartesianGrid strokeDasharray="2 4" stroke="var(--surface-border)" vertical={false} />
              <XAxis dataKey="cve" tick={{ fill: 'var(--text-muted)', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' }}
                angle={-45} textAnchor="end" interval={0} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={CUSTOM_TOOLTIP_STYLE} cursor={{ fill: 'rgba(0,255,65,0.05)' }}
                formatter={(val, name, props) => [`DRS: ${val}`, props.payload.cve]} />
              <Bar dataKey="drs" radius={0}>
                {drsData.map((entry, i) => (
                  <Cell key={i} fill={RISK_COLOR[drsClass(entry.drs)]}
                    style={{ filter: `drop-shadow(0 0 4px ${RISK_COLOR[drsClass(entry.drs)]})` }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>

          {/* DRS table */}
          <table className="cve-table" style={{ marginTop: 12 }} aria-label="DRS score breakdown">
            <thead>
              <tr><th>CVE ID</th><th>CVSS</th><th>EXPLOIT</th><th>SEVERITY</th><th>DRS</th><th>ACTION</th></tr>
            </thead>
            <tbody>
              {drsData.map((d, i) => (
                <tr key={i}>
                  <td style={{ color: RISK_COLOR[drsClass(d.drs)], fontFamily: 'var(--font-mono)', cursor: 'pointer' }}
                    onClick={() => navigate(`/cve/${d.cve}`, { state: { row: scanResults.results[i], product: scanResults.product, version: scanResults.version } })}>
                    {d.cve}
                  </td>
                  <td>{d.cvss.toFixed(1)}</td>
                  <td>{d.exploit ? <span className="badge badge-critical">YES</span> : <span className="badge badge-low">NO</span>}</td>
                  <td><span className={`badge badge-${(d.label || '').toLowerCase()}`}>{d.label}</span></td>
                  <td style={{ color: RISK_COLOR[drsClass(d.drs)], fontWeight: 700 }}>{d.drs}</td>
                  <td>
                    <button className="btn" style={{ padding: '2px 8px', fontSize: 10 }}
                      onClick={() => navigate(`/cve/${d.cve}`, { state: { row: scanResults.results[i], product: scanResults.product, version: scanResults.version } })}>
                      DETAIL &gt;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </SectionBox>
      )}
    </div>
  );
}
