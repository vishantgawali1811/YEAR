# TechStack Detector — Chrome Extension

> A Chrome Extension (Manifest V3) that detects technologies and tech stacks on any website, and seamlessly sends them to your **CVE Intelligence Engine** for vulnerability scanning — no typing required.

---

## 🎯 Project Objective

TechStack Detector is a final-year B.Tech major project extension that bridges **browser-level technology detection** with **CVE vulnerability intelligence**. It answers the question:

> "I'm visiting a site running React 18.2.0 — are there any known CVEs for it?"

**In one click.**

---

## ✨ Features

- 🔍 **Detect technologies** on any webpage (React, Angular, Vue, Next.js, Bootstrap, WordPress, jQuery, and more)
- 🏷️ **Version detection** from script URLs, CDN paths, meta tags, and JavaScript globals
- 📊 **Confidence indicators** — High / Medium / Low per technology
- ⚡ **One-click CVE lookup** — clicking a version badge opens your CVE project and auto-fills the inputs
- ⚙️ **Configurable project URL** — point to any localhost port
- 🛡️ **Secure by design** — no `eval()`, no external network calls, all detection is local

---

## 🏗️ Architecture

```
USER
 │
 ▼
Chrome Browser (any website)
 │
 ▼
Extension Popup (popup.js)
 │  chrome.scripting.executeScript()
 ▼
Content Script (content.js) — runs on the page
 │  Collects: scriptUrls, linkUrls, metas, globals, DOM attrs
 ▼
Detection Engine (detector.js)
 │  Matches clues against 15 technology rules
 ▼
Popup renders results by category
 │
User clicks a version badge (e.g. "18.2.0")
 │  chrome.runtime.sendMessage → service-worker.js
 ▼
service-worker.js opens:
  http://localhost:5173/?technology=React&version=18.2.0
 │
 ▼
Dashboard.jsx reads URLSearchParams on mount
 │
 ▼
✓ Product + Version inputs auto-populated
✓ Banner: "Technology detected from TechStack Detector"
✓ CVE scan auto-triggers after 600ms
```

---

## 📁 Folder Structure

```
tech-stack-detector/
│
├── extension/
│   ├── manifest.json               ← Manifest V3 config
│   │
│   ├── popup/
│   │   ├── popup.html              ← Popup UI
│   │   ├── popup.css               ← Matrix-green styling
│   │   └── popup.js                ← Main popup logic (ES Module)
│   │
│   ├── content/
│   │   └── content.js              ← Injected into target webpage
│   │
│   ├── background/
│   │   └── service-worker.js       ← Opens project website tabs
│   │
│   ├── detectors/
│   │   └── detector.js             ← Detection engine
│   │
│   ├── rules/
│   │   └── technologies.js         ← 15 technology rule definitions
│   │
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
└── README.md
```

---

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| Extension | Chrome Extension Manifest V3 |
| Extension Language | Vanilla JavaScript ES2022+ (ES Modules) |
| Extension UI | HTML5 + CSS3 |
| Project Website | React 19 + Vite 8 |
| Communication | URL Query Parameters |
| Storage | `chrome.storage.local` |

---

## 🚀 Installation

### Step 1 — Load the Extension

1. Open Chrome and navigate to:
   ```
   chrome://extensions
   ```

2. Enable **Developer mode** (toggle in the top-right corner).

3. Click **"Load unpacked"**.

4. Select the folder:
   ```
   tech-stack-detector/extension/
   ```

5. The **TechStack Detector** icon (⚡) will appear in your toolbar.

   > **Tip:** Pin it for easy access — click the puzzle piece icon → pin TechStack Detector.

---

### Step 2 — Run the Project Website

```bash
cd frontend
npm install
npm run dev
```

The project website runs on **http://localhost:5173** by default.

---

### Step 3 — Use It

1. Visit any website (e.g., `https://react.dev`).
2. Click the **TechStack Detector** extension icon.
3. Click **[ SCAN WEBSITE ]**.
4. Results appear by category.
5. Click a version badge (e.g., `18.3.1 →`).
6. Your CVE project opens at:
   ```
   http://localhost:5173/?technology=React&version=18.3.1
   ```
7. The inputs auto-populate and a scan begins automatically.

---

## 🔬 How Technology Detection Works

### Phase 1 — Clue Collection (`content.js`)

When scanning is triggered, the content script collects:

- **Script URLs** — all `<script src="">` attributes
- **CSS Link URLs** — all `<link href="">` attributes  
- **Meta tags** — all `<meta name="..." content="...">` pairs
- **Head HTML** — full `<head>` innerHTML for pattern matching
- **DOM attributes** — pre-queried selectors (e.g., `[ng-version]`)
- **JavaScript globals** — safe property existence checks on `window.*`
- **Global values** — pre-evaluated safe expressions (e.g., `window.React.version`)

### Phase 2 — Pattern Matching (`detector.js`)

Each technology has detection patterns of these types:

| Pattern Type | What it checks |
|---|---|
| `globalVar` | Does `window.React` exist? |
| `scriptUrl` | Does any `<script src>` match `/react\.js/`? |
| `linkUrl` | Does any `<link href>` match `/bootstrap/`? |
| `metaContent` | Does `<meta name="generator">` contain "WordPress"? |
| `htmlSnippet` | Does `<head>` HTML contain `data-reactroot`? |
| `domAttr` | Does any element have `[ng-version]`? |

A technology is **detected** if **at least one** of its patterns matches.

### Phase 3 — Version Extraction

Version patterns are tried in order — first match wins:

1. **JavaScript global expression** — e.g., `window.React.version` → `"18.2.0"`
2. **Script URL regex** — e.g., `/react@([\d.]+)/` on CDN URLs
3. **Meta tag regex** — e.g., `/WordPress\s+([\d.]+)/i` on generator tag
4. **HTML regex** — e.g., `/wp-emoji-release.min.js?ver=([\d.]+)/i`

If no version can be reliably extracted, the badge shows `Unknown` and is **not clickable** (so we never display a fabricated version).

---

## 🔗 How Extension → Website Communication Works

Communication uses **URL Query Parameters** — the simplest and most demo-friendly approach:

```
User clicks "18.2.0" badge
        ↓
popup.js → chrome.runtime.sendMessage({ type: 'OPEN_PROJECT_WEBSITE', ... })
        ↓
service-worker.js → chrome.tabs.create({ url: 'http://localhost:5173/?technology=React&version=18.2.0' })
        ↓
Dashboard.jsx useEffect() on mount:
  const params = new URLSearchParams(window.location.search);
  const technology = params.get('technology'); // "React"
  const version    = params.get('version');    // "18.2.0"
        ↓
setProduct("react") + setVersion("18.2.0")
        ↓
Banner displayed + auto-scan fires after 600ms
```

**Why URL parameters?**
- ✅ Simple to implement and understand
- ✅ Easy to debug (visible in browser address bar during dev)
- ✅ No backend required
- ✅ Works across origins
- ✅ Perfect for a college demo

---

## 🧪 Test Matrix

| Website | Technology | Version Detected? | Click Works? | Fields Populated? |
|---|---|---|---|---|
| `react.dev` | React | ✅ High | ✅ | ✅ |
| `angular.io` | Angular | ✅ High | ✅ | ✅ |
| `vuejs.org` | Vue.js | ✅ High | ✅ | ✅ |
| `jquery.com` | jQuery | ✅ High | ✅ | ✅ |
| `getbootstrap.com` | Bootstrap | ✅ High | ✅ | ✅ |
| Any WP site | WordPress | ✅ Medium | ✅ | ✅ |
| `shopify.com` | Shopify | ✅ Medium | ✅ | ✅ |
| Any GTM site | Google Tag Manager | ✅ (ID) | ✅ | ✅ |

---

## ⚙️ Settings

You can change the project website URL from within the extension:

1. Click **⚙ Settings** in the popup footer.
2. Update the URL (default: `http://localhost:5173`).
3. Click **[ SAVE ]**.

The setting is persisted in `chrome.storage.local`.

---

## ⚠️ Known Limitations

1. **Cannot scan Chrome system pages** — `chrome://`, `chrome-extension://`, `about:` pages are blocked by Chrome's security policy.
2. **Version detection is best-effort** — If a site bundles/minifies code without version identifiers in URLs, version will show as `Unknown`.
3. **HTTP response headers not directly accessible** — Browser extensions cannot read raw HTTP response headers from the current page. Server detection (Nginx, Apache) relies on HTML meta tags or page content hints only.
4. **CSP-restricted pages** — Some heavily locked-down pages may prevent content script injection.
5. **Single-page apps with lazy loading** — If frameworks are loaded dynamically after initial page load, a rescan may be needed.

---

## 🔮 Future Improvements

- [ ] Real-time header reading via `chrome.webRequest` API
- [ ] Export detected tech stack as JSON
- [ ] History of scanned sites
- [ ] Direct `window.postMessage` communication as alternative to URL params
- [ ] More technologies: Svelte, Nuxt, Gatsby, Webpack, Parcel
- [ ] Offline icon pack for all technologies
- [ ] CVE severity preview in the extension popup itself

---

## 📄 License

MIT — free for academic and personal use.
