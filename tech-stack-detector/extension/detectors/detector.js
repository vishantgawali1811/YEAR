/**
 * detector.js — Upgraded Detection Engine (v2)
 *
 * Exports two functions:
 *
 *   1. analyzeTechStack(pageData, rules)  <- NEW primary engine
 *      Wappalyzer-style analysis using the flat rule schema.
 *      Handles: HTTP headers, cookies, meta tags, script URLs, HTML regex.
 *      Supports: regex capture-group version extraction, implies chaining.
 *
 *   2. detect(clues)  <- Legacy adapter kept for popup.js compatibility
 *      Bridges the old clues-object shape into the new engine, then merges
 *      results with legacy globalVar / domAttr pattern matching so no
 *      existing detections regress.
 *
 * ─── New Flat Rule Schema (used by analyzeTechStack) ─────────────────────────
 *
 *  {
 *    name:       string,           // Display name
 *    category:   string,           // Grouping label (Frontend, CMS, …)
 *    icon:       string,           // Emoji (optional)
 *    implies:    string[],         // Names auto-added on match (optional)
 *    confidence: number,           // Base confidence 0-100 (optional, default 75)
 *
 *    headers: { "header-name": /regex/i },   // HTTP response header checks
 *    cookies: { "cookie-name": /regex/i },   // Cookie key/value checks
 *    meta:    { "meta-name":   /regex/i },   // <meta name="…"> content checks
 *    script:  /regex/i,                      // Any script src URL
 *    html:    /regex/i,                      // <head> innerHTML
 *  }
 *
 * Version Extraction (automatic):
 *   If a RegExp contains a capture group, e.g. /jquery\/([\d.]+)/i, the first
 *   captured string is automatically used as the version.
 *
 * ─── pageData Shape (for analyzeTechStack) ────────────────────────────────────
 *
 *  {
 *    headers:    { [name: string]: string },   // lowercase keys
 *    cookies:    { [name: string]: string },   // cookie name → value
 *    metaTags:   { [name: string]: string },   // lowercase name → content
 *    scriptUrls: string[],
 *    htmlHead:   string,                       // <head> innerHTML
 *  }
 */

import { TECHNOLOGIES } from '../rules/technologies.js';

// ─────────────────────────────────────────────────────────────────────────────
// Internal Helpers
// ─────────────────────────────────────────────────────────────────────────────

function isValidVersion(str) {
  if (!str || typeof str !== 'string') return false;
  const s = str.trim();
  if (s.length === 0 || s.length > 20) return false;
  if (/\s/.test(s)) return false; // no spaces allowed
  return true;
}

/**
 * Try to match a RegExp against a string and extract the first capture group
 * as the version. Returns { matched: bool, version: string|null }.
 *
 * @param {RegExp}  re
 * @param {string}  target
 * @returns {{ matched: boolean, version: string|null }}
 */
function matchWithVersion(re, target) {
  if (!(re instanceof RegExp))     return { matched: false, version: null };
  if (typeof target !== 'string')  return { matched: false, version: null };

  const m = target.match(re);
  if (!m) return { matched: false, version: null };

  // Use first capture group as version when present
  const rawVersion = m[1] ? m[1].trim() : null;
  const version = isValidVersion(rawVersion) ? rawVersion : null;
  return { matched: true, version };
}

/**
 * Check a dict of { ruleKey: RegExp } rules against a source dict of
 * { name: stringValue }.  Returns { matched, version } for the first hit.
 *
 * The special ruleKey "*" matches against ALL values in source.
 *
 * @param {Object.<string, RegExp>} rules
 * @param {Object.<string, string>} source
 * @returns {{ matched: boolean, version: string|null }}
 */
function matchDict(rules, source) {
  if (!rules || !source) return { matched: false, version: null };

  for (const [ruleKey, re] of Object.entries(rules)) {
    const key = ruleKey.toLowerCase();

    if (key === '*') {
      for (const val of Object.values(source)) {
        const r = matchWithVersion(re, String(val ?? ''));
        if (r.matched) return r;
      }
      continue;
    }

    const value = source[key];
    if (value == null) continue;

    const r = matchWithVersion(re, String(value));
    if (r.matched) return r;
  }
  return { matched: false, version: null };
}

/**
 * Try matching a single RegExp across an array of strings (e.g. script URLs).
 * Returns the first { matched, version } hit.
 *
 * @param {RegExp}   re
 * @param {string[]} arr
 * @returns {{ matched: boolean, version: string|null }}
 */
function matchArray(re, arr) {
  if (!re || !Array.isArray(arr)) return { matched: false, version: null };
  for (const item of arr) {
    const r = matchWithVersion(re, item);
    if (r.matched) return r;
  }
  return { matched: false, version: null };
}

/**
 * Map a numeric score (0–100) to a confidence label.
 * @param {number} score
 * @returns {'high'|'medium'|'low'}
 */
function scoreToLabel(score) {
  if (score >= 80) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Engine: analyzeTechStack
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Primary detection function using the flat Wappalyzer-style rule schema.
 *
 * @param {Object}   pageData
 * @param {Object}   [pageData.headers]      HTTP response headers (lowercase keys)
 * @param {Object}   [pageData.cookies]      Cookies (name -> value)
 * @param {Object}   [pageData.metaTags]     Meta tag name -> content (lowercase)
 * @param {string[]} [pageData.scriptUrls]   Script src URL list
 * @param {string}   [pageData.htmlHead]     <head> innerHTML
 * @param {Object}   [pageData.jsGlobals]    JS globals extracted from MAIN world
 * @param {Array}    [rules]  Rule objects (defaults to bundled TECHNOLOGIES)
 *
 * @returns {Array<{name, version, category, confidence, icon, score, implied}>}
 */
export function analyzeTechStack(pageData = {}, rules = TECHNOLOGIES) {
  const {
    headers    = {},
    cookies    = {},
    metaTags   = {},
    scriptUrls = [],
    htmlHead   = '',
    jsGlobals  = {},
  } = pageData;

  // Normalize all lookup keys to lowercase for consistent matching
  const normHeaders = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)])
  );
  const normMeta = Object.fromEntries(
    Object.entries(metaTags).map(([k, v]) => [k.toLowerCase(), String(v)])
  );
  const normCookies = Object.fromEntries(
    Object.entries(cookies).map(([k, v]) => [k.toLowerCase(), String(v ?? '')])
  );

  // Master detection map: tech name -> result object
  const detectedMap = new Map();

  /**
   * Evaluate a single rule against all available page signals.
   * Returns { matched, version, score }.
   */
  function evaluateRule(rule) {
    let matched      = false;
    let version      = null;
    let score        = (typeof rule.confidence === 'number') ? rule.confidence : 75;
    let signalsHit   = 0;
    let totalSignals = 0;

    // ── JS Globals (Highest Priority) ───────────────────────────────────────
    if (rule.jsGlobals && Object.keys(rule.jsGlobals).length > 0) {
      totalSignals++;
      for (const [key, valLabel] of Object.entries(rule.jsGlobals)) {
        if (jsGlobals[key] !== undefined && jsGlobals[key] !== null) {
          matched = true;
          signalsHit++;
          const v = String(jsGlobals[key]);
          if (!version && isValidVersion(v) && v !== 'true' && v !== 'Detected') {
            version = v;
          }
        }
      }
    }

    // ── HTTP Response Headers ─────────────────────────────────────────────────
    if (rule.headers && Object.keys(rule.headers).length > 0) {
      totalSignals++;
      const r = matchDict(rule.headers, normHeaders);
      if (r.matched) {
        matched = true; signalsHit++;
        if (r.version && !version) version = r.version;
      }
    }

    // ── Cookies ───────────────────────────────────────────────────────────────
    if (rule.cookies && Object.keys(rule.cookies).length > 0) {
      totalSignals++;
      const r = matchDict(rule.cookies, normCookies);
      if (r.matched) {
        matched = true; signalsHit++;
        if (r.version && !version) version = r.version;
      }
    }

    // ── Meta Tags ─────────────────────────────────────────────────────────────
    if (rule.meta && Object.keys(rule.meta).length > 0) {
      totalSignals++;
      const r = matchDict(rule.meta, normMeta);
      if (r.matched) {
        matched = true; signalsHit++;
        if (r.version && !version) version = r.version;
      }
    }

    // ── Script URLs ───────────────────────────────────────────────────────────
    if (rule.script instanceof RegExp) {
      totalSignals++;
      const r = matchArray(rule.script, scriptUrls);
      if (r.matched) {
        matched = true; signalsHit++;
        if (r.version && !version) version = r.version;
      }
    }

    // ── HTML Head ─────────────────────────────────────────────────────────────
    if (rule.html instanceof RegExp) {
      totalSignals++;
      const r = matchWithVersion(rule.html, htmlHead);
      if (r.matched) {
        matched = true; signalsHit++;
        if (r.version && !version) version = r.version;
      }
    }

    // ── DOM (alias for html) ──────────────────────────────────────────────────
    if (rule.dom instanceof RegExp) {
      totalSignals++;
      const r = matchWithVersion(rule.dom, htmlHead);
      if (r.matched) {
        matched = true; signalsHit++;
        if (r.version && !version) version = r.version;
      }
    }

    // ── Confidence Boost: multiple independent signals increase confidence ─────
    if (totalSignals > 0 && matched) {
      const ratio = signalsHit / totalSignals;
      score = Math.min(100, score + Math.round(ratio * 20));
    }

    return { matched, version, score };
  }

  // ── Pass 1: Run every rule ─────────────────────────────────────────────────
  for (const rule of rules) {
    if (!rule?.name) continue;
    const { matched, version, score } = evaluateRule(rule);
    if (!matched) continue;

    const existing = detectedMap.get(rule.name);
    if (existing) {
      // Upgrade if new signal gives higher score
      if (score > existing._score) {
        existing._score     = score;
        existing.confidence = scoreToLabel(score);
        existing.version    = version ?? existing.version;
      }
    } else {
      detectedMap.set(rule.name, {
        name:      rule.name,
        category:  rule.category || 'Other',
        icon:      rule.icon     || '🔧',
        version:   version       || null,
        confidence: scoreToLabel(score),
        _score:    score,
        _implies:  rule.implies  || [],
        _isImplied: false,
      });
    }
  }

  // ── Pass 2 & 3: Resolve implies (up to 2 levels of chaining) ──────────────
  function resolveImplies(sourceMap, decay) {
    const queue = [];
    for (const result of sourceMap.values()) {
      for (const impliedName of (result._implies || [])) {
        if (!detectedMap.has(impliedName)) {
          queue.push({ impliedName, sourceScore: result._score });
        }
      }
    }
    for (const { impliedName, sourceScore } of queue) {
      if (detectedMap.has(impliedName)) continue;
      const impliedRule  = rules.find(r => r.name === impliedName);
      const impliedScore = Math.max(30, Math.round(sourceScore * decay));
      detectedMap.set(impliedName, {
        name:       impliedName,
        category:   impliedRule?.category || 'Other',
        icon:       impliedRule?.icon     || '🔧',
        version:    null,
        confidence: scoreToLabel(impliedScore),
        _score:     impliedScore,
        _implies:   impliedRule?.implies  || [],
        _isImplied: true,
      });
    }
  }

  resolveImplies(detectedMap, 0.70); // level 1 implies: 70% of parent score
  resolveImplies(detectedMap, 0.65); // level 2 implies: 65% of level-1 score

  // ── Build and sort output array ────────────────────────────────────────────
  const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 };
  const CATEGORY_ORDER   = [
    'Frontend', 'Build Tool', 'CSS', 'UI Framework',
    'CMS', 'Ecommerce', 'Libraries', 'Analytics', 'Tag Manager',
    'Server', 'CDN', 'Security', 'Database', 'Language', 'Other',
  ];

  return [...detectedMap.values()]
    .map(({ name, category, icon, version, confidence, _score, _isImplied }) => ({
      name, category, icon, version, confidence,
      score:   _score,
      implied: _isImplied ?? false,
    }))
    .sort((a, b) => {
      const cA = CATEGORY_ORDER.indexOf(a.category);
      const cB = CATEGORY_ORDER.indexOf(b.category);
      if ((cA === -1 ? 999 : cA) !== (cB === -1 ? 999 : cB))
        return (cA === -1 ? 999 : cA) - (cB === -1 ? 999 : cB);
      const confA = CONFIDENCE_ORDER[a.confidence] ?? 3;
      const confB = CONFIDENCE_ORDER[b.confidence] ?? 3;
      if (confA !== confB) return confA - confB;
      return b.score - a.score;
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy Adapter: detect(clues) — keeps popup.js working unchanged
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Bridges the old clues object (from content.js) into the new engine.
 * Also runs legacy pattern checks (globalVar, domAttr, linkUrl…) that the
 * flat schema cannot express, then merges both result sets.
 *
 * @param {Object} clues  Legacy clues object from content.js
 * @returns {Array}       Merged detection results
 */
export function detect(clues) {
  // ── Map clues -> pageData for new engine ───────────────────────────────────
  const pageData = {
    headers:    clues.responseHeaders || {},
    cookies:    clues.cookies         || {},
    metaTags:   clues.metas           || {},
    scriptUrls: clues.scriptUrls      || [],
    htmlHead:   clues.headHtml        || '',
    jsGlobals:  clues.jsGlobals       || {},
  };

  const newResults   = analyzeTechStack(pageData, TECHNOLOGIES);
  const mergedMap    = new Map(newResults.map(r => [r.name, r]));

  // ── Legacy pattern helpers ─────────────────────────────────────────────────

  function testLegacyPattern(pattern) {
    const { type, value, selector, attr, name, regex } = pattern;
    switch (type) {
      case 'globalVar':
      case 'globalMethod':
        return !!(clues.globals?.[value]);

      case 'scriptUrl': {
        const re = value instanceof RegExp ? value : new RegExp(value, 'i');
        return (clues.scriptUrls || []).some(u => re.test(u));
      }

      case 'linkUrl': {
        const re = value instanceof RegExp ? value : new RegExp(value, 'i');
        return (clues.linkUrls || []).some(u => re.test(u));
      }

      case 'metaContent': {
        const content = (clues.metas || {})[name?.toLowerCase()] || '';
        const re = regex instanceof RegExp ? regex : new RegExp(regex, 'i');
        return re.test(content);
      }

      case 'htmlSnippet': {
        const re = value instanceof RegExp ? value : new RegExp(value, 'i');
        return re.test(clues.headHtml || '');
      }

      case 'domAttr':
      case 'domQuery': {
        const key = (attr || selector || '').replace(/^\[/, '').replace(/\]$/, '');
        const domAttrs = clues.domAttrs || {};
        return domAttrs[key] != null && domAttrs[key] !== false;
      }

      default:
        return false;
    }
  }

  function extractLegacyVersion(versionPatterns) {
    for (const vp of (versionPatterns || [])) {
      switch (vp.type) {
        case 'globalExpr': {
          const keys    = Object.keys(clues.globalValues || {});
          const exprKey = vp.expr.replace(/^window\.?/, '').replace(/window\.?/g, '');
          const match   = keys.find(k =>
            exprKey.includes(k) ||
            k.includes(exprKey.split('&&').pop().trim().replace(/^window\.?/, ''))
          );
          if (match && (clues.globalValues || {})[match]) {
            const v = clues.globalValues[match].trim();
            if (v && v !== 'undefined' && v !== 'null') return { version: v, confidence: 'high' };
          }
          break;
        }
        case 'scriptUrlRegex': {
          const re = vp.regex instanceof RegExp ? vp.regex : new RegExp(vp.regex, 'i');
          for (const url of (clues.scriptUrls || [])) {
            const m = url.match(re);
            if (m?.[vp.group || 1]) return { version: m[vp.group || 1], confidence: 'high' };
          }
          break;
        }
        case 'linkUrlRegex': {
          const re = vp.regex instanceof RegExp ? vp.regex : new RegExp(vp.regex, 'i');
          for (const url of (clues.linkUrls || [])) {
            const m = url.match(re);
            if (m?.[vp.group || 1]) return { version: m[vp.group || 1], confidence: 'high' };
          }
          break;
        }
        case 'metaRegex': {
          const content = (clues.metas || {})[(vp.metaName || '').toLowerCase()] || '';
          const re = vp.regex instanceof RegExp ? vp.regex : new RegExp(vp.regex, 'i');
          const m = content.match(re);
          if (m?.[vp.group || 1]) return { version: m[vp.group || 1], confidence: 'high' };
          break;
        }
        case 'htmlRegex': {
          const re = vp.regex instanceof RegExp ? vp.regex : new RegExp(vp.regex, 'i');
          const m  = (clues.headHtml || '').match(re);
          if (m?.[vp.group || 1]) return { version: m[vp.group || 1], confidence: 'medium', label: vp.label };
          break;
        }
        case 'domAttrRegex': {
          const attrVal = (clues.domAttrs || {})[vp.attr] || '';
          if (!attrVal) break;
          const re = vp.regex instanceof RegExp ? vp.regex : new RegExp(vp.regex, 'i');
          const m  = String(attrVal).match(re);
          if (m?.[vp.group || 1]) return { version: m[vp.group || 1], confidence: 'high' };
          break;
        }
      }
    }
    return { version: null, confidence: 'low' };
  }

  // ── Run legacy rules and merge into mergedMap ──────────────────────────────
  for (const tech of TECHNOLOGIES) {
    if (!tech.patterns || tech.patterns.length === 0) continue;

    const detected = tech.patterns.some(p => testLegacyPattern(p));
    if (!detected) continue;

    const { version, confidence, label } = extractLegacyVersion(tech.versionPatterns || []);
    const matchCount  = tech.patterns.filter(p => testLegacyPattern(p)).length;
    const CONF_SCORE  = { high: 3, medium: 2, low: 1 };

    let finalConf = confidence;
    if (!version) {
      finalConf = matchCount >= 2 ? 'medium' : 'low';
    } else {
      finalConf = confidence === 'high' ? 'high' : matchCount >= 2 ? 'medium' : 'low';
    }

    const existing = mergedMap.get(tech.name);
    if (existing) {
      // Upgrade if legacy gives better version or confidence
      if (
        (version && !existing.version) ||
        (CONF_SCORE[finalConf] > CONF_SCORE[existing.confidence])
      ) {
        existing.version    = version       || existing.version;
        existing.confidence = CONF_SCORE[finalConf] >= CONF_SCORE[existing.confidence]
          ? finalConf
          : existing.confidence;
      }
      if (label) existing.label = label;
    } else {
      mergedMap.set(tech.name, {
        name:       tech.name,
        category:   tech.category || 'Other',
        icon:       tech.icon     || '🔧',
        version:    version       || null,
        confidence: finalConf,
        score:      CONF_SCORE[finalConf] === 3 ? 85 : CONF_SCORE[finalConf] === 2 ? 60 : 35,
        implied:    false,
        label:      label || null,
        matchCount,
      });
    }
  }

  // ── Sort and return merged results ─────────────────────────────────────────
  const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 };
  const CATEGORY_ORDER   = [
    'Frontend', 'Build Tool', 'CSS', 'UI Framework',
    'CMS', 'Ecommerce', 'Libraries', 'Analytics', 'Tag Manager',
    'Server', 'CDN', 'Security', 'Database', 'Language', 'Other',
  ];

  return [...mergedMap.values()].sort((a, b) => {
    const cA = CATEGORY_ORDER.indexOf(a.category);
    const cB = CATEGORY_ORDER.indexOf(b.category);
    if ((cA === -1 ? 999 : cA) !== (cB === -1 ? 999 : cB))
      return (cA === -1 ? 999 : cA) - (cB === -1 ? 999 : cB);
    const confA = CONFIDENCE_ORDER[a.confidence] ?? 3;
    const confB = CONFIDENCE_ORDER[b.confidence] ?? 3;
    if (confA !== confB) return confA - confB;
    return (b.score ?? 0) - (a.score ?? 0);
  });
}
