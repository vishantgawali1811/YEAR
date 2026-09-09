import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { lookup, computeDRS, drsClass } from '../api/cveApi.js';

const RISK_COLOR = {
  critical: 'var(--risk-critical)',
  high:     'var(--risk-high)',
  medium:   'var(--risk-medium)',
  low:      'var(--risk-low)',
};

function RiskGauge({ drs }) {
  const cls = drsClass(drs);
  const color = RISK_COLOR[cls];
  const circumference = 2 * Math.PI * 42;
  const offset = circumference - (drs / 100) * circumference;

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width="120" height="120" viewBox="0 0 100 100" aria-label={`DRS Score: ${drs} out of 100`}>
        {/* background ring */}
        <circle cx="50" cy="50" r="42" fill="none" stroke="var(--surface-mid)" strokeWidth="8" />
        {/* progress ring */}
        <circle
          cx="50" cy="50" r="42" fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="square"
          transform="rotate(-90 50 50)"
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'stroke-dashoffset 1s ease' }}
        />
        {/* center text */}
        <text x="50" y="46" textAnchor="middle" fill={color}
          fontFamily="JetBrains Mono, monospace" fontSize="18" fontWeight="700">
          {drs}
        </text>
        <text x="50" y="60" textAnchor="middle" fill="var(--text-muted)"
          fontFamily="JetBrains Mono, monospace" fontSize="8">
          /100
        </text>
      </svg>
      <div style={{ fontSize: 'var(--fs-xs)', color, fontWeight: 700, letterSpacing: '0.1em', marginTop: 4 }}>
        DRS: {cls.toUpperCase()}
      </div>
    </div>
  );
}

function WeightBar({ label, weight, value, maxValue, color }) {
  const pct = Math.min(100, (value / maxValue) * 100);
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--fs-xs)', marginBottom: 4 }}>
        <span style={{ color: 'var(--text-secondary)' }}>{label} <span style={{ color: 'var(--text-muted)' }}>(weight {weight}%)</span></span>
        <span style={{ color }}>{typeof value === 'boolean' ? (value ? 'YES' : 'NO') : value}</span>
      </div>
      <div className="progress-bar-track">
        <div className="progress-bar-fill" style={{ width: `${pct}%`, background: color, boxShadow: `0 0 4px ${color}` }} />
      </div>
    </div>
  );
}

function TypewriterText({ text, speed = 18 }) {
  const [displayed, setDisplayed] = useState('');
  useEffect(() => {
    setDisplayed('');
    let i = 0;
    const id = setInterval(() => {
      if (i < text.length) { setDisplayed(text.slice(0, ++i)); } else clearInterval(id);
    }, speed);
    return () => clearInterval(id);
  }, [text, speed]);

  return (
    <span>
      {displayed}
      {displayed.length < text.length && <span className="cursor-underscore" />}
    </span>
  );
}

export default function CVEDetail() {
  const { cveId } = useParams();
  const { state } = useLocation();
  const navigate = useNavigate();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Use pre-fetched row from navigation state, then enrich with AI summary
  const rawRow = state?.row;
  const product = state?.product || '';
  const version = state?.version || '';

  useEffect(() => {
    if (!product || !version) {
      setError('Missing product/version context. Please return to the dashboard and click Analyze from there.');
      return;
    }
    setLoading(true);
    lookup(product, version)
      .then(resp => {
        const match = resp.results?.find(r => r.cve_id === cveId) || resp.results?.[0];
        setData({ ...resp, matchedRow: match });
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [cveId, product, version]);

  const row = data?.matchedRow || rawRow;
  const drs = row ? computeDRS(row.cvss, row.label, row.exploit) : 0;
  const cls = drsClass(drs);
  const color = RISK_COLOR[cls];
  const summary = row?.summary || data?.matchedRow?.summary || null;

  // Build operator phrase for display
  const opPhrase = { '<': 'earlier than', '<=': 'up to and including', '==': 'exactly', '>': 'later than', '>=': 'starting from' };

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', marginBottom: 12 }}>
        <button className="btn-ghost btn" style={{ padding: '2px 8px', fontSize: 10 }} onClick={() => navigate(-1)}>
          ← BACK
        </button>
        <span style={{ margin: '0 8px' }}>/</span>
        <span>TRIAGE</span>
        <span style={{ margin: '0 8px' }}>&gt;</span>
        <span style={{ color: 'var(--primary)' }}>{cveId}</span>
      </div>

      {error && (
        <div role="alert" style={{ color: 'var(--risk-critical)', fontSize: 'var(--fs-sm)', padding: 'var(--sp-5)', border: '1px solid var(--risk-critical)', background: 'var(--risk-critical-bg)' }}>
          ERROR: {error}
        </div>
      )}

      {!row && loading && (
        <div style={{ textAlign: 'center', padding: 'var(--sp-10)', color: 'var(--text-muted)' }}>
          <div className="spinner" style={{ width: 32, height: 32, margin: '0 auto 12px' }} />
          <div>LOADING CVE INTELLIGENCE…</div>
        </div>
      )}

      {row && (
        <>
          {/* ── CVE Header ─────────────────────────── */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 'var(--sp-5)', flexWrap: 'wrap' }}>
            <div>
              <h1 style={{ fontSize: 'var(--fs-2xl)', fontWeight: 700, color, textShadow: `0 0 16px ${color}`, fontFamily: 'var(--font-mono)', marginBottom: 8 }}>
                {cveId}
              </h1>
              <span className={`badge badge-${(row.label || '').toLowerCase()}`} style={{ fontSize: 'var(--fs-xs)' }}>
                {row.label || 'UNKNOWN'} SEVERITY
              </span>
              {loading && <span style={{ marginLeft: 12, fontSize: 'var(--fs-xs)', color: 'var(--text-muted)' }}>
                <span className="spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} /> Loading AI summary…
              </span>}
            </div>
            <RiskGauge drs={drs} />
          </div>

          {/* ── Sections grid ──────────────────────── */}
          <div className="grid-2" style={{ gap: 'var(--sp-4)', marginBottom: 'var(--sp-4)' }}>

            {/* A: Entity Identification */}
            <div className="terminal-box" style={{ padding: 'var(--sp-5)', paddingTop: 'var(--sp-6)' }}>
              <div className="terminal-box-title">// ENTITY_IDENTIFICATION</div>
              <div style={{ lineHeight: 2.2, fontSize: 'var(--fs-sm)' }}>
                {[
                  ['PRODUCT',  row.product],
                  ['VERSION',  `${opPhrase[row.operator] || row.operator} ${row.version}`],
                  ['ATTACK_VECTOR', row.attack_vector],
                  ['PRIVILEGES',   row.privileges],
                  ['CVE_ID',  cveId],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--surface-border)', paddingBottom: 4 }}>
                    <span style={{ color: 'var(--primary-dim)', minWidth: 130, fontSize: 'var(--fs-xs)', fontWeight: 700 }}>{k}:</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{v || '—'}</span>
                  </div>
                ))}
                <div style={{ display: 'flex', gap: 8, paddingTop: 4 }}>
                  <span style={{ color: 'var(--primary-dim)', minWidth: 130, fontSize: 'var(--fs-xs)', fontWeight: 700 }}>EXPLOIT:</span>
                  <span>{row.exploit
                    ? <span className="badge badge-critical">ACTIVE</span>
                    : <span className="badge badge-low">NONE KNOWN</span>}
                  </span>
                </div>
              </div>
            </div>

            {/* B: Risk Score Breakdown */}
            <div className="terminal-box" style={{ padding: 'var(--sp-5)', paddingTop: 'var(--sp-6)' }}>
              <div className="terminal-box-title">// RISK_SCORE_BREAKDOWN</div>
              <div style={{ marginBottom: 12 }}>
                <WeightBar
                  label="CVSS SEVERITY"
                  weight={50}
                  value={`${parseFloat(row.cvss || 0).toFixed(1)} / 10`}
                  maxValue={1}
                  color="var(--risk-critical)"
                />
                <div className="progress-bar-track" style={{ marginTop: -10, marginBottom: 14 }}>
                  <div className="progress-bar-fill" style={{
                    width: `${(parseFloat(row.cvss || 0) / 10) * 100}%`,
                    background: 'var(--risk-critical)',
                    boxShadow: '0 0 4px var(--risk-critical)',
                  }} />
                </div>

                <WeightBar
                  label="EXPLOIT AVAIL."
                  weight={30}
                  value={row.exploit ? 'CONFIRMED' : 'NOT FOUND'}
                  maxValue={1}
                  color="var(--risk-high)"
                />
                <div className="progress-bar-track" style={{ marginTop: -10, marginBottom: 14 }}>
                  <div className="progress-bar-fill" style={{
                    width: row.exploit ? '100%' : '10%',
                    background: 'var(--risk-high)',
                  }} />
                </div>

                <WeightBar
                  label="SEVERITY LEVEL"
                  weight={20}
                  value={row.label}
                  maxValue={1}
                  color="var(--risk-medium)"
                />
                <div className="progress-bar-track" style={{ marginTop: -10 }}>
                  <div className="progress-bar-fill" style={{
                    width: row.label === 'CRITICAL' ? '100%' : row.label === 'HIGH' ? '75%' : row.label === 'MEDIUM' ? '50%' : '25%',
                    background: 'var(--risk-medium)',
                  }} />
                </div>
              </div>

              <div style={{ borderTop: '1px solid var(--surface-border)', paddingTop: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)' }}>DYNAMIC RISK SCORE</span>
                <span className={`drs-number drs-${cls}`} style={{ fontSize: 28 }}>{drs}<span style={{ fontSize: 14 }}>/100</span></span>
              </div>
            </div>
          </div>

          {/* C: Description */}
          <div className="terminal-box" style={{ padding: 'var(--sp-5)', paddingTop: 'var(--sp-6)', marginBottom: 'var(--sp-4)' }}>
            <div className="terminal-box-title">// VULNERABILITY_DESCRIPTION</div>
            <p style={{ fontSize: 'var(--fs-base)', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
              {row.description}
            </p>
          </div>

          {/* D: AI Narrative */}
          <div className="terminal-box" style={{ padding: 'var(--sp-5)', paddingTop: 'var(--sp-6)', marginBottom: 'var(--sp-4)' }}>
            <div className="terminal-box-title">// AI_ATTACK_NARRATIVE</div>
            <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--primary-dim)', marginBottom: 8 }}>
              &gt; AI_NARRATIVE.load() :: Flan-T5-Base :: RAG pipeline
            </div>
            {loading && !summary && (
              <div style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-sm)' }}>
                <span className="spinner" style={{ width: 14, height: 14, borderWidth: 1.5 }} />
                {' '}Generating AI summary… (this may take 10–30 seconds)
              </div>
            )}
            {summary && (
              <p style={{ fontSize: 'var(--fs-base)', color: 'var(--text-primary)', lineHeight: 1.9, fontStyle: 'italic' }}>
                <TypewriterText text={summary} speed={20} />
              </p>
            )}
            {!loading && !summary && (
              <div style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-sm)' }}>
                AI summary will appear here once the Flan-T5 model finishes inference.
              </div>
            )}
          </div>

          {/* ── Action bar ─────────────────────────── */}
          <div style={{ display: 'flex', gap: 'var(--sp-3)', flexWrap: 'wrap', paddingTop: 'var(--sp-2)' }}>
            <button id="btn-back" className="btn btn-ghost" onClick={() => navigate(-1)}>[ ← BACK_TO_TRIAGE ]</button>
            <button id="btn-copy" className="btn" onClick={() => navigator.clipboard?.writeText(cveId)}>[ COPY_CVE_ID ]</button>
            <a
              id="btn-nvd"
              href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn"
              style={{ textDecoration: 'none' }}
            >
              [ VIEW_ON_NVD ↗ ]
            </a>
          </div>
        </>
      )}
    </div>
  );
}
