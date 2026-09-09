/**
 * service-worker.js — Background Service Worker (Manifest V3)
 *
 * Minimal service worker. Its main job is to:
 *   1. Open the project website tab when a version badge is clicked.
 *   2. Relay messages between popup and content scripts if needed.
 *
 * The popup handles most logic directly; this is kept intentionally lean.
 */

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {

  // ── Open Project Website with URL params ──────────────────────────────────
  if (message.type === 'OPEN_PROJECT_WEBSITE') {
    const { technology, version, projectUrl } = message.payload;

    // Build the URL with query parameters
    const base = projectUrl || 'http://localhost:5175';
    const params = new URLSearchParams();
    if (technology) params.set('technology', technology);
    if (version)    params.set('version', version);

    const fullUrl = `${base}/?${params.toString()}`;

    // Check if a project website tab is already open
    chrome.tabs.query({ url: `${base}/*` }, (existingTabs) => {
      if (existingTabs && existingTabs.length > 0) {
        // Update the existing tab and navigate to new URL
        chrome.tabs.update(existingTabs[0].id, { url: fullUrl, active: true }, () => {
          chrome.windows.update(existingTabs[0].windowId, { focused: true });
        });
      } else {
        // Open a new tab
        chrome.tabs.create({ url: fullUrl });
      }
      sendResponse({ success: true, url: fullUrl });
    });

    return true; // Keep message channel open for async callback
  }

  return false;
});

// Extension installed / updated
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[TechStack Detector] Installed. Visit any website and click the extension icon.');
  }
});
