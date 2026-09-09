import React, { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { healthCheck } from '../api/cveApi';

const NAV = [
  { path: '/',          label: 'TRIAGE',   icon: '⬡', abbr: 'TRG' },
  { path: '/terminal',  label: 'TERMINAL', icon: '>_', abbr: 'TRM' },
  { path: '/analysis',  label: 'ANALYSIS', icon: '◈',  abbr: 'ANL' },
];

const SIDEBAR_STYLE = {
  width: 'var(--sidebar-w)',
  minWidth: 'var(--sidebar-w)',
  height: '100vh',
  background: 'var(--surface)',
  borderRight: '1px solid var(--surface-border)',
  display: 'flex',
  flexDirection: 'column',
  flexShrink: 0,
  overflow: 'hidden',
};

export default function Sidebar() {
  const location = useLocation();
  const [apiOk, setApiOk] = useState(null);

  useEffect(() => {
    healthCheck().then(setApiOk).catch(() => setApiOk(false));
    const id = setInterval(() => healthCheck().then(setApiOk).catch(() => setApiOk(false)), 15000);
    return () => clearInterval(id);
  }, []);

  return (
    <aside style={SIDEBAR_STYLE} aria-label="Main navigation">
      {/* Brand */}
      <div style={{ padding: '16px 16px 12px', borderBottom: '1px solid var(--surface-border)' }}>
        <div style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', letterSpacing: '0.1em', marginBottom: 4 }}>
          // SYSTEM
        </div>
        <div style={{ color: 'var(--primary)', fontWeight: 700, fontSize: 'var(--fs-sm)', textShadow: 'var(--primary-glow-sm)' }}>
          CVE_INTEL_ENGINE
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>v2.0.0 :: RAG + FLAN-T5</div>
      </div>

      {/* API Status */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--surface-border)', fontSize: 'var(--fs-xs)' }}>
        <span style={{ color: 'var(--text-muted)' }}>API_STATUS: </span>
        {apiOk === null && <span style={{ color: 'var(--text-muted)' }}>CHECKING...</span>}
        {apiOk === true  && <span style={{ color: 'var(--risk-low)' }}>● ONLINE</span>}
        {apiOk === false && <span style={{ color: 'var(--risk-critical)' }}>● OFFLINE</span>}
      </div>

      {/* Nav Links */}
      <nav style={{ padding: '8px 0', flex: 1 }}>
        <div style={{ padding: '8px 16px', fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
          // NAVIGATION
        </div>
        {NAV.map(({ path, label, abbr }) => (
          <NavLink
            key={path}
            to={path}
            end={path === '/'}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '10px 16px',
              textDecoration: 'none',
              color: isActive ? 'var(--primary)' : 'var(--text-muted)',
              background: isActive ? 'var(--surface-low)' : 'transparent',
              borderLeft: isActive ? '3px solid var(--primary)' : '3px solid transparent',
              fontSize: 'var(--fs-xs)',
              fontWeight: 700,
              letterSpacing: '0.08em',
              transition: 'all 0.15s',
              textShadow: isActive ? 'var(--primary-glow-sm)' : 'none',
            })}
          >
            <span style={{ fontFamily: 'monospace', fontSize: 12 }}>[{abbr}]</span>
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* System info */}
      <div style={{ padding: '12px 16px', borderTop: '1px solid var(--surface-border)', fontSize: 10, color: 'var(--text-muted)' }}>
        <div>// PIPELINE</div>
        <div style={{ marginTop: 4, lineHeight: 1.8 }}>
          <div>► Retrieval: CSV+Pandas</div>
          <div>► Parser: Regex+NLP</div>
          <div>► Generator: Flan-T5-Base</div>
        </div>
      </div>
    </aside>
  );
}
