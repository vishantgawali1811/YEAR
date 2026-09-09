/**
 * popup.js — Extension Popup Logic
 *
 * Responsibilities:
 *  1. Get the current tab info (URL / hostname).
 *  2. Inject the content script and request clues.
 *  3. Run the detection engine against the clues.
 *  4. Render technology cards grouped by category.
 *  5. Handle version badge clicks → open project website.
 *  6. Manage settings (project URL stored in chrome.storage.local).
 *  7. Handle all error / loading / empty states gracefully.
 */

import { detect } from '../detectors/detector.js';

// ─── Constants ────────────────────────────────────────────────────────────────
const DEFAULT_PROJECT_URL = 'http://localhost:5175';
const STORAGE_KEY_URL     = 'projectWebsiteUrl';

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $scanBtn          = document.getElementById('scan-btn');
const $scanBtnText      = document.getElementById('scan-btn-text');
const $hostname         = document.getElementById('site-hostname');
const $statusText       = document.getElementById('status-text');
const $statusDot        = document.querySelector('.live-dot');
const $stateLoading     = document.getElementById('state-loading');
const $stateError       = document.getElementById('state-error');
const $stateEmpty       = document.getElementById('state-empty');
const $resultsContainer = document.getElementById('results-container');
const $resultsList      = document.getElementById('results-list');
const $resultsCount     = document.getElementById('results-count');
const $errorTitle       = document.getElementById('error-title');
const $errorDetail      = document.getElementById('error-detail');
const $footerSettings   = document.getElementById('footer-settings');
const $settingsPanel    = document.getElementById('settings-panel');
const $projectUrlInput  = document.getElementById('project-url-input');
const $saveSettingsBtn  = document.getElementById('save-settings-btn');
const $settingsHint     = document.getElementById('settings-save-hint');

// ─── State ────────────────────────────────────────────────────────────────────
let currentTab       = null;
let projectUrl       = DEFAULT_PROJECT_URL;
let hasScanned       = false;

// ─── Utility Functions ────────────────────────────────────────────────────────

function showState(which) {
  $stateLoading.classList.add('hidden');
  $stateError.classList.add('hidden');
  $stateEmpty.classList.add('hidden');
  $resultsContainer.classList.add('hidden');
  if (which === 'loading')  $stateLoading.classList.remove('hidden');
  if (which === 'error')    $stateError.classList.remove('hidden');
  if (which === 'empty')    $stateEmpty.classList.remove('hidden');
  if (which === 'results')  $resultsContainer.classList.remove('hidden');
}

function setStatus(text, mode = 'ready') {
  $statusText.textContent = text;
  $statusDot.className = 'live-dot';
  if (mode === 'scanning') $statusDot.classList.add('scanning');
  if (mode === 'error')    $statusDot.classList.add('error');
}

function sanitize(str) {
  // Simple text sanitization — no HTML injection possible
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/[<>&"']/g, c => ({
    '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function isProtectedPage(url) {
  if (!url) return true;
  return url.startsWith('chrome://') ||
         url.startsWith('chrome-extension://') ||
         url.startsWith('about:') ||
         url.startsWith('edge://') ||
         url.startsWith('devtools://') ||
         url === 'about:blank';
}

// ─── Load Settings ────────────────────────────────────────────────────────────
async function loadSettings() {
  try {
    const result = await chrome.storage.local.get([STORAGE_KEY_URL]);
    if (result[STORAGE_KEY_URL]) {
      projectUrl = result[STORAGE_KEY_URL];
      $projectUrlInput.value = projectUrl;
    } else {
      $projectUrlInput.value = DEFAULT_PROJECT_URL;
    }
  } catch {
    $projectUrlInput.value = DEFAULT_PROJECT_URL;
  }
}

// ─── Save Settings ────────────────────────────────────────────────────────────
async function saveSettings() {
  const url = $projectUrlInput.value.trim();
  if (!url) {
    $settingsHint.textContent = 'URL cannot be empty.';
    $settingsHint.style.color = 'var(--risk-critical)';
    return;
  }
  try {
    await chrome.storage.local.set({ [STORAGE_KEY_URL]: url });
    projectUrl = url;
    $settingsHint.textContent = '✓ Saved!';
    $settingsHint.style.color = 'var(--risk-low)';
    setTimeout(() => { $settingsHint.textContent = ''; }, 2000);
  } catch {
    $settingsHint.textContent = 'Failed to save.';
    $settingsHint.style.color = 'var(--risk-critical)';
  }
}

// ─── Get Current Tab ──────────────────────────────────────────────────────────
async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// ─── Inject Content Script & Get Clues ───────────────────────────────────────
async function getClues(tabId) {
  // Inject the content script
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ['content/content.js'],
  });

  // Wait a moment for the script to register its listener
  await new Promise(resolve => setTimeout(resolve, 150));

  // Request the clues from the ISOLATED world
  const clues = await new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: 'GET_CLUES' }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response || !response.success) {
        reject(new Error('Content script did not respond correctly.'));
        return;
      }
      resolve(response.clues);
    });
  });

  // Extract jsGlobals from the MAIN world (bypassing isolated world)
  try {
    const globalsResult = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: () => {
        function safeGet(expr) {
          try {
            const parts = expr.replace(/^window\.?/, '').split('.');
            let obj = window;
            for (const part of parts) {
              if (obj == null) return undefined;
              obj = obj[part];
            }
            return obj;
          } catch {
            return undefined;
          }
        }
        const safeExpressions = [
          'React.version', 'Vue.version', '__VUE__.version', 'angular.version.full',
          'jQuery.fn.jquery', 'bootstrap.Tooltip.VERSION', 'Shopify.version', '__NEXT_DATA__.buildId',
          'webpackChunk'
        ];
        const vals = {};
        for (const expr of safeExpressions) {
          const val = safeGet(expr);
          if (val) vals[expr] = String(val);
        }
        try {
          const hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
          if (hook && hook.renderers && hook.renderers.size > 0) {
            const renderer = [...hook.renderers.values()][0];
            if (renderer && renderer.version) {
              vals['ReactDevTools.version'] = String(renderer.version);
            }
          }
        } catch {}
        return vals;
      }
    });

    clues.jsGlobals = (globalsResult && globalsResult[0] && globalsResult[0].result) || {};
  } catch (err) {
    console.warn('[TechStack] Failed to fetch MAIN world globals:', err);
    clues.jsGlobals = {};
  }

  return clues;
}

// ─── Render Results ───────────────────────────────────────────────────────────
function renderResults(technologies) {
  $resultsList.innerHTML = '';

  if (technologies.length === 0) {
    showState('empty');
    return;
  }

  $resultsCount.textContent = technologies.length;

  // Group by category
  const groups = {};
  for (const tech of technologies) {
    if (!groups[tech.category]) groups[tech.category] = [];
    groups[tech.category].push(tech);
  }

  for (const [category, techs] of Object.entries(groups)) {
    // Category header
    const catDiv = document.createElement('div');
    catDiv.className = 'category-group';

    const catLabel = document.createElement('div');
    catLabel.className = 'category-label';
    catLabel.textContent = `// ${category.toUpperCase()}`;
    catDiv.appendChild(catLabel);

    // Tech cards
    for (const tech of techs) {
      const card = createTechCard(tech);
      catDiv.appendChild(card);
    }

    $resultsList.appendChild(catDiv);
  }

  showState('results');
}

function createTechCard(tech) {
  const card = document.createElement('div');
  card.className = 'tech-card';
  card.setAttribute('role', 'article');
  card.setAttribute('aria-label', `${tech.name}${tech.version ? ` version ${tech.version}` : ''}`);

  // Left side — icon + name + confidence
  const left = document.createElement('div');
  left.className = 'tech-card-left';

  const iconEl = document.createElement('span');
  iconEl.className = 'tech-icon';
  iconEl.textContent = tech.icon || '🔧';
  iconEl.setAttribute('aria-hidden', 'true');

  const infoEl = document.createElement('div');
  infoEl.className = 'tech-info';

  const nameEl = document.createElement('div');
  nameEl.className = 'tech-name';
  nameEl.textContent = sanitize(tech.name);

  const confEl = document.createElement('div');
  confEl.className = 'tech-confidence';

  const confDot = document.createElement('span');
  confDot.className = `conf-dot ${tech.confidence}`;
  confDot.setAttribute('aria-hidden', 'true');

  const confLabel = document.createElement('span');
  confLabel.className = `conf-label ${tech.confidence}`;
  confLabel.textContent = `${tech.confidence.toUpperCase()} confidence`;

  confEl.appendChild(confDot);
  confEl.appendChild(confLabel);
  infoEl.appendChild(nameEl);
  infoEl.appendChild(confEl);

  // Sub-label for special versions (e.g. "GA4" or "GTM-XXXXXX")
  if (tech.label) {
    const subLabel = document.createElement('div');
    subLabel.className = 'version-sub-label';
    subLabel.textContent = sanitize(tech.label);
    infoEl.appendChild(subLabel);
  }

  left.appendChild(iconEl);
  left.appendChild(infoEl);

  // Right side — version badge
  const badge = document.createElement('button');
  badge.className = 'version-badge';

  if (tech.version) {
    badge.setAttribute('aria-label', `Query CVE Engine for ${tech.name} version ${tech.version}`);
    badge.setAttribute('title', `Click to query: ${tech.name} ${tech.version}`);

    const versionText = document.createTextNode(sanitize(tech.version));
    const arrowEl = document.createElement('span');
    arrowEl.className = 'version-badge-arrow';
    arrowEl.textContent = '→';
    arrowEl.setAttribute('aria-hidden', 'true');

    badge.appendChild(versionText);
    badge.appendChild(arrowEl);

    badge.addEventListener('click', () => handleVersionClick(tech, badge));
  } else {
    badge.className = 'version-badge unknown';
    badge.textContent = 'Unknown';
    badge.setAttribute('aria-label', `${tech.name} version unknown`);
    badge.disabled = true;
  }

  card.appendChild(left);
  card.appendChild(badge);
  return card;
}

// ─── Handle Version Click ─────────────────────────────────────────────────────
async function handleVersionClick(tech, badgeEl) {
  // Visual feedback — flash the badge
  badgeEl.classList.add('clicked');
  setTimeout(() => badgeEl.classList.remove('clicked'), 400);

  const technology = tech.name;
  const version    = tech.version;

  // Tell the background service worker to open the project website
  chrome.runtime.sendMessage({
    type: 'OPEN_PROJECT_WEBSITE',
    payload: { technology, version, projectUrl },
  }, (response) => {
    if (chrome.runtime.lastError) {
      console.warn('[TechStack] Could not open project website:', chrome.runtime.lastError.message);
    }
    if (response && response.url) {
      console.log('[TechStack] Opened:', response.url);
    }
  });
}

// ─── Main Scan Flow ───────────────────────────────────────────────────────────
async function scan() {
  if (!currentTab) return;

  setStatus('SCANNING', 'scanning');
  showState('loading');
  $scanBtn.disabled = true;
  $scanBtnText.textContent = '[ SCANNING… ]';

  try {
    const clues = await getClues(currentTab.id);
    const results = detect(clues);

    hasScanned = true;
    setStatus(`${results.length} FOUND`, 'ready');
    $scanBtnText.textContent = '[ RESCAN ]';
    $scanBtn.disabled = false;
    renderResults(results);

  } catch (err) {
    console.error('[TechStack Detector] Scan error:', err);

    let title  = 'Scan failed';
    let detail = err.message || 'Unknown error occurred.';

    if (detail.includes('Cannot access') || detail.includes('chrome://') || detail.includes('Cannot read')) {
      title  = 'Cannot access this page';
      detail = 'Chrome system pages and extension pages cannot be scanned.';
    } else if (detail.includes('No tab') || detail.includes('not respond')) {
      title  = 'Page not ready';
      detail = 'The page may still be loading. Try again in a moment.';
    } else if (detail.includes('permission')) {
      title  = 'Permission denied';
      detail = 'Reload the page and try again, or check extension permissions.';
    }

    $errorTitle.textContent  = title;
    $errorDetail.textContent = detail;
    setStatus('ERROR', 'error');
    $scanBtnText.textContent = '[ RETRY ]';
    $scanBtn.disabled = false;
    showState('error');
  }
}

// ─── Initialization ───────────────────────────────────────────────────────────
async function init() {
  await loadSettings();

  // Get current tab info
  try {
    currentTab = await getCurrentTab();
    if (currentTab && currentTab.url) {
      const url = new URL(currentTab.url);
      $hostname.textContent = url.hostname || currentTab.url;
    } else {
      $hostname.textContent = 'Unknown page';
    }
  } catch {
    $hostname.textContent = 'Unknown page';
  }

  // Check if page is protected
  if (!currentTab || isProtectedPage(currentTab.url)) {
    $errorTitle.textContent  = 'Cannot analyze this page';
    $errorDetail.textContent = 'Chrome system pages and extension pages cannot be scanned.';
    showState('error');
    setStatus('UNAVAILABLE', 'error');
    $scanBtn.disabled = true;
    return;
  }

  // Event: Scan button
  $scanBtn.addEventListener('click', scan);

  // Event: Settings toggle
  $footerSettings.addEventListener('click', () => {
    $settingsPanel.classList.toggle('hidden');
  });

  // Event: Save settings
  $saveSettingsBtn.addEventListener('click', saveSettings);

  // Event: Enter key in settings input
  $projectUrlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') saveSettings();
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
