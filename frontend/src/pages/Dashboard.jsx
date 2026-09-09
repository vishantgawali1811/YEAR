import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { agentQuery, drsClass, labelClass } from '../api/cveApi.js';

/* ── Risk colour helpers ─────────────────────────────────── */
const RISK_COLOR = { critical: 'var(--risk-critical)', high: 'var(--risk-high)', medium: 'var(--risk-medium)', low: 'var(--risk-low)' };

function StatCard({ label, value, cls }) {
  return (
    <div className={`stat-card ${cls}`} role="region" aria-label={`${label}: ${value}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-sub">CVEs indexed</div>
    </div>
  );
}

function DRSBadge({ drs }) {
  const cls = drsClass(drs);
  return (
    <span style={{ color: RISK_COLOR[cls], fontWeight: 700, fontSize: 15, textShadow: `0 0 8px ${RISK_COLOR[cls]}` }}>
      {drs}
    </span>
  );
}

function ExploitBadge({ exploit }) {
  return exploit
    ? <span className="badge badge-critical">ACTIVE</span>
    : <span className="badge badge-low">NONE</span>;
}

function CvssBar({ cvss }) {
  const v = parseFloat(cvss) || 0;
  const pct = (v / 10) * 100;
  const cls = v >= 9 ? 'critical' : v >= 7 ? 'high' : v >= 4 ? 'medium' : 'low';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div className="progress-bar-track" style={{ width: 60 }}>
        <div className="progress-bar-fill" style={{ width: `${pct}%`, background: RISK_COLOR[cls] }} />
      </div>
      <span style={{ fontSize: 'var(--fs-xs)', color: RISK_COLOR[cls] }}>{v.toFixed(1)}</span>
    </div>
  );
}

export default function Dashboard({ stats }) {
  const navigate = useNavigate();
  const [product, setProduct] = useState('');
  const [version, setVersion] = useState('');
  const [queryMode, setQueryMode] = useState('lookup');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [searched, setSearched] = useState(false);

  const handleSearch = useCallback(async (e) => {
    e.preventDefault();
    if (!product.trim() || !version.trim()) {
      setError('ERROR: Both product and version are required.');
      return;
    }
    setError('');
    setLoading(true);
    setSearched(false);
    try {
      const normalizedProduct = product.trim().toLowerCase();
      const normalizedVersion = version.trim();
      const queryString = queryMode === 'remediation'
        ? `how do I fix ${normalizedProduct} ${normalizedVersion}?`
        : `is ${normalizedProduct} ${normalizedVersion} vulnerable?`;
      const data = await agentQuery(queryString);
      setResults(data);
      setSearched(true);
    } catch (err) {
      setError(`ERROR: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [product, version, queryMode]);

  const rows = results?.results || [];
  const isRemediation = results?.intent === 'remediation';

  // Stats breakdown from props (global) or current search results
  const critCount = stats?.critical ?? 0;
  const highCount  = stats?.high     ?? 0;
  const medCount   = stats?.medium   ?? 0;
  const lowCount   = stats?.low      ?? 0;

  return (
    <div>
      {/* ── Page header ───────────────────────────── */}
      <div className="page-header">
        <div>
          <div className="page-title">
            <span className="live-dot" style={{ marginRight: 10 }} />
            VULNERABILITY TRIAGE MATRIX
          </div>
          <div className="page-subtitle">
            {stats?.total ? `${stats.total.toLocaleString()} CVEs indexed` : 'Loading dataset…'}
            &nbsp;·&nbsp;Enter product + version to query
          </div>
        </div>
        <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', textAlign: 'right' }}>
          <div>ENGINE: ONLINE</div>
          <div>MODEL: FLAN-T5-BASE</div>
        </div>
      </div>

      {/* ── KPI Cards ─────────────────────────────── */}
      <div className="grid-4" style={{ marginBottom: 'var(--sp-6)' }}>
        <StatCard label="CRITICAL" value={critCount} cls="critical" />
        <StatCard label="HIGH"     value={highCount}  cls="high"     />
        <StatCard label="MEDIUM"   value={medCount}   cls="medium"   />
        <StatCard label="LOW"      value={lowCount}   cls="low"      />
      </div>

      {/* ── Search form ───────────────────────────── */}
      <div className="terminal-box" style={{ padding: 'var(--sp-5)', marginBottom: 'var(--sp-5)' }}>
        <div className="terminal-box-title">// QUERY_INTERFACE</div>
      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
        {[
          ['lookup', 'LOOKUP'],
          ['remediation', 'FIX / REMEDIATION'],
        ].map(([mode, label]) => (
          <button
            key={mode}
            type="button"
            className={`btn ${queryMode === mode ? '' : 'btn-ghost'}`}
            style={{ padding: '3px 10px', fontSize: 10 }}
            onClick={() => setQueryMode(mode)}
            aria-pressed={queryMode === mode}
          >
            {label}
          </button>
        ))}
      </div>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 'var(--sp-3)', flexWrap: 'wrap', marginTop: 8 }}>
          <div style={{ flex: 1, minWidth: 160 }}>
            <label htmlFor="product-input" style={{ display: 'block', fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>
              PRODUCT:
            </label>
            <input
              id="product-input"
              className="terminal-input"
              placeholder="e.g. pan-os, android, sql_server"
              value={product}
              onChange={e => setProduct(e.target.value)}
              aria-describedby={error ? 'search-error' : undefined}
            />
          </div>
          <div style={{ flex: 1, minWidth: 140 }}>
            <label htmlFor="version-input" style={{ display: 'block', fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>
              VERSION:
            </label>
            <input
              id="version-input"
              className="terminal-input"
              placeholder="e.g. 8.1.20, 12.0, 9.0.5"
              value={version}
              onChange={e => setVersion(e.target.value)}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button id="search-btn" type="submit" className="btn" disabled={loading} aria-busy={loading}>
              {loading ? <><span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} /> SCANNING…</> : '[ SCAN_CVE ]'}
            </button>
          </div>
        </form>
        {error && (
          <div id="search-error" role="alert" style={{ marginTop: 8, fontSize: 'var(--fs-xs)', color: 'var(--risk-critical)' }}>
            {error}
          </div>
        )}
        {searched && !error && (
          <div style={{ marginTop: 8, fontSize: 'var(--fs-xs)', color: 'var(--primary)' }}>
            &gt; SCAN COMPLETE: {rows.length} vulnerabilit{rows.length === 1 ? 'y' : 'ies'} found for {results?.product} {results?.version}
           {results?.intent && (
             <span className={`badge badge-${results.intent === 'remediation' ? 'high' : 'low'}`} style={{ marginLeft: 8 }}>
               DETECTED: {results.intent.toUpperCase()}
             </span>
           )}
            {results?.message && <span style={{ color: 'var(--risk-low)' }}> :: {results.message}</span>}
          </div>
        )}
      </div>

      {/* ── Results table ─────────────────────────── */}
      {searched && (
        <div className="terminal-box" style={{ padding: 0 }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--surface-border)' }}>
            <span className="terminal-box-title" style={{ position: 'static', background: 'none', padding: 0 }}>
              // CVE_RESULTS :: {results?.product?.toUpperCase()} {results?.version}
            </span>
          </div>
          {rows.length === 0 ? (
            <div style={{ padding: 'var(--sp-8)', textAlign: 'center', color: 'var(--risk-low)', fontSize: 'var(--fs-sm)' }}>
              <div style={{ fontSize: 24, marginBottom: 8 }}>✓</div>
              <div>NO VULNERABILITIES FOUND</div>
              <div style={{ color: 'var(--text-muted)', marginTop: 4, fontSize: 'var(--fs-xs)' }}>
                {results?.product} {results?.version} has no known CVEs in the dataset.
              </div>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="cve-table" aria-label="CVE results table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>PRODUCT</th>
                    <th>VERSION</th>
                    {isRemediation ? (
                      <th>REMEDIATION</th>
                    ) : (
                      <>
                        <th>CVSS</th>
                        <th>SEVERITY</th>
                        <th>EXPLOIT</th>
                        <th>ATTACK VECTOR</th>
                      </>
                    )}
                    <th>DRS SCORE</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, i) => (
                    <tr key={`${row.cve_id}-${i}`}>
                      <td>
                        <span
                          className="cve-id-cell"
                          onClick={() => navigate(`/cve/${row.cve_id}`, { state: { row, product: results?.product, version: results?.version } })}
                          role="button"
                          tabIndex={0}
                          onKeyDown={e => e.key === 'Enter' && navigate(`/cve/${row.cve_id}`, { state: { row, product: results?.product, version: results?.version } })}
                          aria-label={`View details for ${row.cve_id}`}
                          title="Click to view full CVE details"
                        >
                          {row.cve_id}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{row.product}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--fs-xs)', color: 'var(--text-muted)' }}>
                        {row.operator} {row.version}
                      </td>
                      {isRemediation ? (
                        <td>
                          {row.remediation?.length ? (
                            <ul style={{ margin: 0, paddingLeft: 18 }}>
                              {row.remediation.map((step, stepIndex) => <li key={stepIndex}>{step}</li>)}
                            </ul>
                          ) : '—'}
                        </td>
                      ) : (
                        <>
                          <td><CvssBar cvss={row.cvss} /></td>
                          <td><span className={`badge badge-${labelClass(row.priority_label)}`}>{row.priority_label || '—'}</span></td>
                          <td><ExploitBadge exploit={row.exploit} /></td>
                          <td style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                            {row.attack_vector || '—'}
                          </td>
                        </>
                      )}
                      <td><DRSBadge drs={row.risk_score} /></td>
                      <td>
                        <button
                          className="btn"
                          style={{ padding: '3px 10px', fontSize: 10 }}
                          onClick={() => navigate(`/cve/${row.cve_id}`, { state: { row, product: results?.product, version: results?.version } })}
                          aria-label={`Analyze ${row.cve_id}`}
                        >
                          ANALYZE &gt;
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Prompt before search ───────────────────── */}
      {!searched && (
        <div style={{
          border: '1px solid var(--surface-border)',
          padding: 'var(--sp-10)',
          textAlign: 'center',
          color: 'var(--text-muted)',
          background: 'var(--surface)',
        }}>
          <div style={{ fontSize: 'var(--fs-lg)', color: 'var(--primary-dim)', marginBottom: 8 }}>
            {'> AWAITING_QUERY █'}
          </div>
          <div style={{ fontSize: 'var(--fs-sm)' }}>
            Enter a product name and version above to scan for vulnerabilities.
          </div>
          <div style={{ marginTop: 8, fontSize: 'var(--fs-xs)', lineHeight: 2 }}>
            <span style={{ color: 'var(--primary-dim)' }}>Examples: </span>
            {[['pan-os', '8.1.20'], ['android', '12.0'], ['sql_server', '15.0.2000']].map(([p, v]) => (
              <button key={p} className="btn-ghost btn" style={{ margin: '0 4px', padding: '2px 8px', fontSize: 10 }}
                onClick={() => { setProduct(p); setVersion(v); }}>
                {p} {v}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
