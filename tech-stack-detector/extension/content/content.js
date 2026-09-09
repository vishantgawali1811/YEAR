/**
 * content.js — Content Script
 *
 * Runs in the context of the inspected webpage when the extension requests it.
 * Collects all detectable "clues" from the DOM and page context, then returns
 * them to the popup via chrome.runtime.sendMessage.
 *
 * Clues collected:
 *   - All <script> src attributes
 *   - All <link> href attributes
 *   - All <meta> name/content pairs
 *   - The full <head> innerHTML (for pattern matching)
 *   - Window-level globals (via a safe property check)
 *   - The page URL
 */

(function () {
  'use strict';

  /**
   * Safely gets a window property. Never throws.
   */
  function safeGet(expr) {
    try {
      // We only evaluate simple property chains — never arbitrary code.
      // This resolves things like "window.React.version" safely.
      const parts = expr.replace(/^window\.?/, '').split('.');
      let obj = window;
      for (const part of parts) {
        if (obj == null || typeof obj !== 'object' && typeof obj !== 'function') return undefined;
        obj = obj[part];
      }
      return obj;
    } catch {
      return undefined;
    }
  }

  /**
   * Check if a global variable exists on the window object.
   */
  function globalExists(name) {
    try {
      return name in window && window[name] !== undefined && window[name] !== null;
    } catch {
      return false;
    }
  }

  // ── Collect Script URLs ───────────────────────────────────────────────────
  const scriptUrls = [];
  document.querySelectorAll('script[src]').forEach(el => {
    scriptUrls.push(el.getAttribute('src') || '');
  });

  // ── Collect Link (CSS) URLs ───────────────────────────────────────────────
  const linkUrls = [];
  document.querySelectorAll('link[rel][href]').forEach(el => {
    linkUrls.push(el.getAttribute('href') || '');
  });

  // ── Collect Meta Tags ─────────────────────────────────────────────────────
  const metas = {};
  document.querySelectorAll('meta[name]').forEach(el => {
    const name = (el.getAttribute('name') || '').toLowerCase();
    const content = el.getAttribute('content') || '';
    metas[name] = content;
  });
  // Also grab http-equiv metas (e.g. server headers sometimes appear here)
  document.querySelectorAll('meta[http-equiv]').forEach(el => {
    const name = (el.getAttribute('http-equiv') || '').toLowerCase();
    const content = el.getAttribute('content') || '';
    metas[`http-equiv:${name}`] = content;
  });

  // ── Head HTML ─────────────────────────────────────────────────────────────
  const headHtml = (document.head || document.documentElement).innerHTML || '';

  // ── DOM Attributes ────────────────────────────────────────────────────────
  // Pre-query common selectors to avoid repeated DOM access in detector
  const domAttrs = {
    'ng-version': (() => {
      const el = document.querySelector('[ng-version]');
      return el ? el.getAttribute('ng-version') : null;
    })(),
    '_nghost': (() => {
      // Find any element with an attribute starting with _nghost
      const el = document.querySelector('[_nghost-ng-]') || document.querySelector('[_nghost]');
      return el ? true : null;
    })(),
    'data-v-app': (() => {
      const el = document.querySelector('[data-v-app]');
      return el ? 'present' : null;
    })(),
  };

  // ── Global Variables ──────────────────────────────────────────────────────
  // We check a predetermined safe list — no arbitrary eval
  const globalChecks = [
    '__REACT_DEVTOOLS_GLOBAL_HOOK__',
    'React',
    '__react_root__',
    'ng',
    'angular',
    'Vue',
    '__VUE__',
    '__vue_app__',
    '__NEXT_DATA__',
    '__next_router_basepath',
    'bootstrap',
    'jQuery',
    '$',
    'gtag',
    'ga',
    'google_tag_manager',
    'Shopify',
  ];

  const globals = {};
  for (const key of globalChecks) {
    globals[key] = globalExists(key);
  }

  // ── Global Expressions (safe value extraction) ─────────────────────────────
  // Only for known, safe expressions that return version strings
  const globalValues = {};
  const safeExpressions = {
    'React.version':          'React.version',
    'Vue.version':            'Vue.version',
    '__VUE__.version':        '__VUE__.version',
    'angular.version.full':   'angular.version.full',
    'jQuery.fn.jquery':       'jQuery.fn.jquery',
    'bootstrap.Tooltip.VERSION': 'bootstrap.Tooltip.VERSION',
    'Shopify.version':        'Shopify.version',
    '__NEXT_DATA__.buildId':  '__NEXT_DATA__.buildId',
  };

  for (const [label, expr] of Object.entries(safeExpressions)) {
    try {
      const val = safeGet(expr);
      if (val !== undefined && val !== null) {
        globalValues[label] = String(val);
      }
    } catch {
      // ignore
    }
  }

  // ── React DevTools Hook (version extraction) ──────────────────────────────
  try {
    const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (hook && hook.renderers && hook.renderers.size > 0) {
      const renderer = [...hook.renderers.values()][0];
      if (renderer && renderer.version) {
        globalValues['ReactDevTools.version'] = String(renderer.version);
      }
    }
  } catch {
    // ignore
  }

  // ── Assemble Clues Object ─────────────────────────────────────────────────
  const clues = {
    url: window.location.href,
    hostname: window.location.hostname,
    scriptUrls,
    linkUrls,
    metas,
    headHtml,
    domAttrs,
    globals,
    globalValues,
  };

  // ── Send clues back to popup ──────────────────────────────────────────────
  // The popup uses chrome.tabs.sendMessage to request clues.
  // We respond to the 'getClues' message.
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === 'GET_CLUES') {
      sendResponse({ success: true, clues });
    }
    return true; // keep channel open for async
  });

})();
