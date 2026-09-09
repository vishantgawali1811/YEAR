import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { agentQuery, lookupRaw, computeDRS, drsClass } from '../api/cveApi.js';

const RISK_COLOR = { critical: 'var(--risk-critical)', high: 'var(--risk-high)', medium: 'var(--risk-medium)', low: 'var(--risk-low)' };

const BOOT_LINES = [
  { text: '[BOOT] Initializing CVE Intelligence Engine v2.0…', delay: 0,    color: 'var(--text-muted)' },
  { text: '[OK]   Dataset loaded: 3310 CVE records', delay: 300,  color: 'var(--risk-low)' },
  { text: '[OK]   Retrieval layer: Pandas + packaging ready', delay: 500,  color: 'var(--risk-low)' },
  { text: '[OK]   NLP parser: Regex + keyword matching active', delay: 700,  color: 'var(--risk-low)' },
  { text: '[OK]   Generation model: google/flan-t5-base loaded', delay: 900,  color: 'var(--risk-low)' },
  { text: '[OK]   FastAPI server: http://localhost:8000', delay: 1100, color: 'var(--risk-low)' },
  { text: '[SYS]  Type a query or use --product / --version flags.', delay: 1400, color: 'var(--primary)' },
  { text: '[SYS]  Example: "is pan-os 8.1.20 vulnerable?"', delay: 1600, color: 'var(--primary)' },
  { text: '> System ready. Type a query below.', delay: 1900, color: 'var(--primary)' },
];

const HELP_TEXT = `
AVAILABLE COMMANDS:
  help                     — show this message
  clear                    — clear terminal output
  scan <product> <version> — lookup CVEs directly (no AI)
  query <natural language> — intent-aware free-text CVE query
  
EXAMPLES:
  scan pan-os 8.1.20
  scan android 12.0
  query is pan-os 8.1.20 vulnerable?
  query check firefox version 3.4.5
  query any known CVEs for android 12.0
`.trim();

export default function Terminal() {
  const navigate = useNavigate();
  const [lines, setLines] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [histIdx, setHistIdx] = useState(-1);
  const bottomRef = useRef(null);
  const inputRef = useRef(null);
  const booted = useRef(false);

  const addLine = useCallback((text, color = 'var(--text-secondary)', isError = false) => {
    setLines(prev => [...prev, { text, color: isError ? 'var(--risk-critical)' : color, id: Date.now() + Math.random() }]);
  }, []);

  // Boot sequence
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    BOOT_LINES.forEach(({ text, delay, color }) => {
      setTimeout(() => addLine(text, color), delay);
    });
  }, [addLine]);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const printResults = useCallback((resp) => {
    if (!resp.parsed_ok) {
      addLine(`[WARN] ${resp.message}`, 'var(--risk-medium)');
      return;
    }
    if (resp.results.length === 0) {
      addLine(`[OK]   No vulnerabilities found for ${resp.product} ${resp.version}.`, 'var(--risk-low)');
      return;
    }
    addLine(`[OK]   ${resp.results.length} CVE(s) found for ${resp.product} ${resp.version}:`, 'var(--primary)');
    resp.results.forEach(r => {
      const drs = computeDRS(r.cvss, r.label, r.exploit);
      const cls = drsClass(drs);
      addLine(
        `       ${r.cve_id}  CVSS:${r.cvss}  DRS:${drs}  ${r.label}  EXPLOIT:${r.exploit ? 'YES' : 'NO'}`,
        RISK_COLOR[cls]
      );
      if (r.summary) {
        addLine(`       [AI] ${r.summary}`, 'var(--text-secondary)');
      }
      if (resp.intent === 'remediation' && r.remediation) {
        r.remediation.forEach(step => {
          addLine(`       ${step}`, 'var(--text-secondary)');
        });
      }
      if (resp.intent === 'remediation' && r.remediation_detail) {
        addLine(`       [DETAIL] ${r.remediation_detail}`, 'var(--text-secondary)');
      }
    });
  }, [addLine]);

  const runCommand = useCallback(async (cmd) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    addLine(`$ ${trimmed}`, 'var(--primary)');
    setHistory(prev => [trimmed, ...prev.slice(0, 49)]);
    setHistIdx(-1);

    const parts = trimmed.split(/\s+/);
    const verb = parts[0].toLowerCase();

    if (verb === 'clear') {
      setLines([]);
      return;
    }
    if (verb === 'help') {
      HELP_TEXT.split('\n').forEach(l => addLine(l, 'var(--text-secondary)'));
      return;
    }

    // scan <product> <version>
    if (verb === 'scan') {
      const [, product, version, ...rest] = parts;
      if (!product || !version) {
        addLine('[ERR]  Usage: scan <product> <version>', 'var(--risk-critical)');
        return;
      }
      setLoading(true);
      addLine(`[SYS]  Scanning ${product} ${version}… (no AI summary)`, 'var(--text-muted)');
      try {
        const resp = await lookupRaw(product, version);
        printResults(resp);
      } catch (e) {
        addLine(`[ERR]  ${e.message}`, 'var(--risk-critical)', true);
      } finally {
        setLoading(false);
      }
      return;
    }

    // query <natural language>
    if (verb === 'query') {
      const question = parts.slice(1).join(' ');
      if (!question) {
        addLine('[ERR]  Usage: query <natural language question>', 'var(--risk-critical)');
        return;
      }
      setLoading(true);
      addLine(`[NLP]  Parsing: "${question}"…`, 'var(--text-muted)');
      addLine('[NLP]  Routing by intent…', 'var(--text-muted)');
      try {
        const resp = await agentQuery(question);
        if (resp.product && resp.version) {
          addLine(`[NLP]  Detected: product="${resp.product}" version="${resp.version}"`, 'var(--primary-dim)');
        }
        printResults(resp);
      } catch (e) {
        addLine(`[ERR]  ${e.message}`, 'var(--risk-critical)', true);
      } finally {
        setLoading(false);
      }
      return;
    }

    // Unknown — try free-text query as fallback
    addLine(`[SYS]  Unknown command. Trying as NLP query…`, 'var(--text-muted)');
    setLoading(true);
    try {
      const resp = await agentQuery(trimmed);
      if (resp.product && resp.version) {
        addLine(`[NLP]  Detected: product="${resp.product}" version="${resp.version}"`, 'var(--primary-dim)');
      }
      printResults(resp);
    } catch (e) {
      addLine(`[ERR]  ${e.message} — type "help" for usage.`, 'var(--risk-critical)', true);
    } finally {
      setLoading(false);
    }
  }, [addLine, printResults]);

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Enter' && !loading) {
      runCommand(input);
      setInput('');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const idx = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(idx);
      setInput(history[idx] || '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      const idx = Math.max(histIdx - 1, -1);
      setHistIdx(idx);
      setInput(idx === -1 ? '' : (history[idx] || ''));
    }
  }, [input, loading, history, histIdx, runCommand]);

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">TERMINAL :: CLI_INTERFACE</div>
          <div className="page-subtitle">Direct commands · NLP queries · Flan-T5 AI summaries</div>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 10 }} onClick={() => setLines([])}>
          [ CLEAR ]
        </button>
      </div>

      {/* Terminal window */}
      <div
        style={{
          flex: 1,
          background: 'var(--surface)',
          border: '1px solid var(--primary-dim)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          minHeight: 400,
        }}
        onClick={() => inputRef.current?.focus()}
        role="log"
        aria-live="polite"
        aria-label="Terminal output"
      >
        {/* Window bar */}
        <div style={{ padding: '6px 12px', borderBottom: '1px solid var(--surface-border)', display: 'flex', alignItems: 'center', gap: 6, background: 'var(--surface-low)' }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#FF5F56', display: 'inline-block' }} />
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#FFBD2E', display: 'inline-block' }} />
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#27C93F', display: 'inline-block' }} />
          <span style={{ marginLeft: 12, fontSize: 10, color: 'var(--text-muted)' }}>CVE_INTELLIGENCE_ENGINE :: TERMINAL v2.0</span>
        </div>

        {/* Output */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: 'var(--fs-sm)', lineHeight: 1.8 }}>
          {lines.map(line => (
            <div key={line.id} style={{ color: line.color, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {line.text}
            </div>
          ))}
          {loading && (
            <div style={{ color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} />
              PROCESSING…
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Input line */}
        <div style={{ borderTop: '1px solid var(--surface-border)', padding: '8px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: 'var(--primary)', fontWeight: 700, flexShrink: 0 }}>$&gt;</span>
          <input
            ref={inputRef}
            id="terminal-input"
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--fs-sm)',
              caretColor: 'var(--primary)',
            }}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            aria-label="Terminal command input"
            placeholder={loading ? '' : 'Type a command or NLP query…'}
          />
        </div>
      </div>

      {/* Quick commands */}
      <div style={{ marginTop: 12, fontSize: 'var(--fs-xs)', color: 'var(--text-muted)', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <span>QUICK:</span>
        {[
          'scan pan-os 8.1.20',
          'scan android 12.0',
          'query is sql_server 15.0 vulnerable?',
          'help',
        ].map(cmd => (
          <button key={cmd} className="btn btn-ghost" style={{ padding: '1px 8px', fontSize: 10 }}
            onClick={() => { setInput(cmd); inputRef.current?.focus(); }}>
            {cmd}
          </button>
        ))}
      </div>
    </div>
  );
}
