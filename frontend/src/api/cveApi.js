// API base URL — change to your production URL when deploying
const BASE_URL = '';

/**
 * POST /lookup-raw  — fast lookup without AI summary
 * @param {string} product
 * @param {string} version
 */
export async function lookupRaw(product, version) {
  const res = await fetch(`${BASE_URL}/lookup-raw`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ product, version }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * POST /lookup  — lookup with AI-generated Flan-T5 summary
 * @param {string} product
 * @param {string} version
 */
export async function lookup(product, version) {
  const res = await fetch(`${BASE_URL}/lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ product, version }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * POST /query  — free-text NLP query (parses product+version then looks up)
 * @param {string} query  e.g. "is pan-os 8.1.20 vulnerable?"
 */
export async function queryFreeText(query) {
  const res = await fetch(`${BASE_URL}/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

/**
 * GET /stats  — dataset summary for KPI tiles
 */
export async function getStats() {
  const res = await fetch(`${BASE_URL}/stats`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * GET /  — health check
 */
export async function healthCheck() {
  const res = await fetch(`${BASE_URL}/`);
  return res.ok;
}

/**
 * Compute Dynamic Risk Score (DRS) client-side from CVE fields.
 * Formula mirrors the presentation spec:
 *   CVSS weight: 50% of 10-point scale → max 50 pts
 *   Exploit availability: if exploit=true → 50 pts, else 0 (maps to 20% conceptually)
 *   Severity proxy: label bonus for urgency → remaining 30 pts
 * Returns 0–100 integer.
 */
export function computeDRS(cvss, label, exploit) {
  const cvssScore = (parseFloat(cvss) || 0) / 10 * 50;  // 0–50
  const exploitScore = exploit ? 30 : 5;                 // 30 or 5
  const severityBonus =
    label === 'CRITICAL' ? 20 :
    label === 'HIGH'     ? 15 :
    label === 'MEDIUM'   ? 8  : 3;                       // 0–20
  return Math.min(100, Math.round(cvssScore + exploitScore + severityBonus));
}

/** Map DRS score (0–100) to a risk class string */
export function drsClass(drs) {
  if (drs >= 80) return 'critical';
  if (drs >= 60) return 'high';
  if (drs >= 40) return 'medium';
  return 'low';
}

/** Map label string to CSS class */
export function labelClass(label) {
  return (label || '').toLowerCase();
}
