import React, { useState } from 'react';

const STYLE = {
  height: 'var(--topnav-h)',
  background: 'var(--surface)',
  borderBottom: '1px solid var(--surface-border)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '0 20px',
  flexShrink: 0,
};

export default function TopNav({ threatLevel = 'CRITICAL', totalCves = 0 }) {
  const [time, setTime] = React.useState(() => new Date().toISOString().slice(11, 19));

  React.useEffect(() => {
    const id = setInterval(() => setTime(new Date().toISOString().slice(11, 19) + 'Z'), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header style={STYLE} aria-label="Top navigation bar">
      {/* Left: branding */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <span style={{ color: 'var(--primary)', fontWeight: 700, fontSize: 'var(--fs-sm)', textShadow: 'var(--primary-glow-sm)', letterSpacing: '0.05em' }}>
          &gt; CVE_INTELLIGENCE_ENGINE
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          :: {totalCves > 0 ? totalCves.toLocaleString() : '—'} CVEs indexed
        </span>
      </div>

      {/* Right: status indicators */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {/* Clock */}
        <span style={{ fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          UTC {time}
        </span>

        {/* Threat badge */}
        <span
          className={`badge badge-${threatLevel === 'CRITICAL' ? 'critical' : threatLevel === 'HIGH' ? 'high' : 'medium'}`}
          aria-label={`Current threat level: ${threatLevel}`}
        >
          <span className="live-dot red" style={{ width: 6, height: 6, marginRight: 6 }} />
          THREAT: {threatLevel}
        </span>

        {/* User */}
        <div
          aria-label="User: SOC Analyst"
          title="SOC Analyst"
          style={{
            width: 28, height: 28,
            border: '1px solid var(--primary-dim)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 'var(--fs-xs)', color: 'var(--primary)', cursor: 'pointer',
          }}
        >
          [A]
        </div>
      </div>
    </header>
  );
}
