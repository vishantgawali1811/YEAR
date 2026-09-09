/**
 * technologies.js — Detection rules for all supported technologies.
 *
 * Each rule has:
 *   name        — display name
 *   category    — grouping label shown in popup
 *   icon        — emoji icon for quick visual reference
 *   implies     — array of technologies implied by this one
 *
 * New Flat Schema (for v2 engine):
 *   headers     — { "header-name": /regex/i }
 *   cookies     — { "cookie-name": /regex/i }
 *   meta        — { "meta-name": /regex/i }
 *   script      — /regex/i against script src
 *   html        — /regex/i against head HTML
 *   dom         — /regex/i against head HTML (alias)
 *
 * Legacy Schema (for backward compatibility):
 *   patterns    — array of detection patterns (objects with type + value)
 *   versionPatterns — ordered array of patterns to attempt version extraction
 */

export const TECHNOLOGIES = [

  // ─── FRONTEND & FRAMEWORKS ──────────────────────────────────────────────────

  {
    name: "React",
    category: "Frontend",
    icon: "⚛️",
    confidence: 80,
    jsGlobals: { "React.version": "version" },
    script: /react(?:\.min)?\.js/i,
    html: /data-reactroot|data-reactid/i,
    patterns: [
      { type: "globalVar",    value: "__REACT_DEVTOOLS_GLOBAL_HOOK__" },
      { type: "globalVar",    value: "React" },
      { type: "globalVar",    value: "__react_root__" },
      { type: "scriptUrl",    value: /react(?:\.min)?\.js/ },
      { type: "scriptUrl",    value: /react-dom(?:\.min)?\.js/ },
      { type: "htmlSnippet",  value: /data-reactroot/i },
      { type: "htmlSnippet",  value: /data-reactid/i },
    ],
    versionPatterns: [
      { type: "globalExpr",     expr: "window.React && window.React.version" },
      { type: "globalExpr",     expr: "window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size > 0 && [...window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.values()][0].version" },
      { type: "scriptUrlRegex", regex: /react(?:\.min)?\.js\?v=([\d.]+)/i,   group: 1 },
      { type: "scriptUrlRegex", regex: /react@([\d.]+)/i,                     group: 1 },
    ]
  },

  {
    name: "Angular",
    category: "Frontend",
    icon: "🔺",
    confidence: 80,
    jsGlobals: { "angular.version.full": "version" },
    script: /angular(?:\.min)?\.js/i,
    html: /ng-version|\[_nghost\]/i,
    dom: /ng-version="([\d.]+)"/i,
    patterns: [
      { type: "globalVar",   value: "ng" },
      { type: "globalVar",   value: "angular" },
      { type: "domAttr",     selector: "[ng-version]", attr: "ng-version" },
      { type: "domQuery",    selector: "[_nghost]" },
      { type: "scriptUrl",   value: /angular(?:\.min)?\.js/ },
      { type: "htmlSnippet", value: /ng-version/i },
    ],
    versionPatterns: [
      { type: "domAttrRegex", selector: "[ng-version]", attr: "ng-version", regex: /([\d.]+)/, group: 1 },
      { type: "globalExpr",   expr: "window.angular && window.angular.version && window.angular.version.full" },
      { type: "scriptUrlRegex", regex: /angular[@/]([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Vue.js",
    category: "Frontend",
    icon: "💚",
    confidence: 80,
    jsGlobals: { "Vue.version": "version", "__VUE__.version": "version" },
    script: /vue(?:\.min)?\.js/i,
    html: /data-v-[a-z0-9]+/i,
    dom: /data-v-app/i,
    patterns: [
      { type: "globalVar",   value: "Vue" },
      { type: "globalVar",   value: "__VUE__" },
      { type: "globalVar",   value: "__vue_app__" },
      { type: "domAttr",     selector: "[data-v-app]", attr: "data-v-app" },
      { type: "scriptUrl",   value: /vue(?:\.min)?\.js/ },
      { type: "htmlSnippet", value: /data-v-[a-z0-9]+/i },
    ],
    versionPatterns: [
      { type: "globalExpr",     expr: "window.Vue && window.Vue.version" },
      { type: "globalExpr",     expr: "window.__VUE__ && window.__VUE__.version" },
      { type: "scriptUrlRegex", regex: /vue[@/]([\d.]+)/i, group: 1 },
      { type: "scriptUrlRegex", regex: /vue(?:\.min)?\.js\?v=([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Svelte",
    category: "Frontend",
    icon: "🔥",
    html: /svelte-[a-z0-9]+/i,
    patterns: [
      { type: "htmlSnippet", value: /svelte-[a-z0-9]+/i }
    ]
  },

  {
    name: "Next.js",
    category: "Frontend",
    icon: "▲",
    implies: ["React", "Node.js"],
    meta: { "generator": /next\.js/i },
    script: /\/_next\/static\//i,
    html: /__NEXT_DATA__/i,
    patterns: [
      { type: "globalVar",    value: "__NEXT_DATA__" },
      { type: "globalVar",    value: "__next_router_basepath" },
      { type: "scriptUrl",    value: /\/_next\/static\// },
      { type: "htmlSnippet",  value: /__NEXT_DATA__/i },
      { type: "metaContent",  name: "generator", regex: /next\.js/i },
    ],
    versionPatterns: [
      { type: "globalExpr",     expr: "window.__NEXT_DATA__ && window.__NEXT_DATA__.buildId" },
      { type: "htmlRegex",      regex: /"nextjs":\s*"([\d.]+)"/i,   group: 1 },
      { type: "scriptUrlRegex", regex: /next\/([\d.]+)\//i,          group: 1 },
      { type: "metaRegex",      metaName: "generator", regex: /next\.js\s+([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Nuxt.js",
    category: "Frontend",
    icon: "⛰️",
    implies: ["Vue.js", "Node.js"],
    script: /\/_nuxt\//i,
    html: /__NUXT__/i,
    patterns: [
      { type: "globalVar", value: "__NUXT__" },
      { type: "scriptUrl", value: /\/_nuxt\// }
    ]
  },

  {
    name: "Gatsby",
    category: "Frontend",
    icon: "🟣",
    implies: ["React"],
    meta: { "generator": /gatsby/i },
    html: /id="___gatsby"/i,
    patterns: [
      { type: "metaContent", name: "generator", regex: /gatsby/i },
      { type: "domQuery", selector: "#___gatsby" }
    ],
    versionPatterns: [
      { type: "metaRegex", metaName: "generator", regex: /gatsby\s+([\d.]+)/i, group: 1 }
    ]
  },

  // ─── BUILD TOOLS ────────────────────────────────────────────────────────────

  {
    name: "Vite",
    category: "Build Tool",
    icon: "⚡",
    script: /\/@vite\/client/i,
    patterns: [
      { type: "scriptUrl",   value: /\/@vite\/client/ },
      { type: "scriptUrl",   value: /vite\.svg/ },
      { type: "htmlSnippet", value: /@vite\/client/i },
    ],
    versionPatterns: [
      { type: "scriptUrlRegex", regex: /vite[@/]([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Webpack",
    category: "Build Tool",
    icon: "📦",
    jsGlobals: { "webpackChunk": "Detected" },
    script: /webpack/i,
    patterns: [
      { type: "globalVar", value: "webpackChunk" }
    ]
  },

  // ─── CSS & UI FRAMEWORKS ────────────────────────────────────────────────────

  {
    name: "Bootstrap",
    category: "CSS",
    icon: "🅱️",
    html: /class="[^"]*(?:container|row|col-(?:xs|sm|md|lg|xl))[^"]*"/i,
    patterns: [
      { type: "linkUrl",     value: /bootstrap(?:\.min)?\.css/ },
      { type: "scriptUrl",   value: /bootstrap(?:\.min)?\.js/ },
      { type: "htmlSnippet", value: /class="[^"]*(?:container|row|col-(?:xs|sm|md|lg|xl))[^"]*"/i },
      { type: "globalVar",   value: "bootstrap" },
    ],
    versionPatterns: [
      { type: "globalExpr",   expr: "window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION" },
      { type: "linkUrlRegex", regex: /bootstrap[@/]([\d.]+)/i,               group: 1 },
      { type: "linkUrlRegex", regex: /bootstrap(?:\.min)?\.css\?v=([\d.]+)/i, group: 1 },
      { type: "scriptUrlRegex", regex: /bootstrap[@/]([\d.]+)/i,             group: 1 },
    ]
  },

  {
    name: "Tailwind CSS",
    category: "CSS",
    icon: "🌊",
    html: /class="[^"]*(?:flex|grid|text-\w+-\d+|bg-\w+-\d+|p-\d+|m-\d+)[^"]*"/i,
    patterns: [
      { type: "scriptUrl",   value: /tailwind(?:css)?(?:\.min)?\.js/ },
      { type: "linkUrl",     value: /tailwind(?:css)?(?:\.min)?\.css/ },
      { type: "htmlSnippet", value: /class="[^"]*(?:flex|grid|text-\w+-\d+|bg-\w+-\d+|p-\d+|m-\d+)[^"]*"/i },
    ],
    versionPatterns: [
      { type: "scriptUrlRegex", regex: /tailwind(?:css)?[@/]([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Material UI",
    category: "UI Framework",
    icon: "Ⓜ️",
    implies: ["React"],
    html: /class="[^"]*Mui[A-Z][a-z]+/i,
    patterns: [
      { type: "htmlSnippet", value: /class="[^"]*Mui[A-Z][a-z]+/i }
    ]
  },

  {
    name: "Ant Design",
    category: "UI Framework",
    icon: "🐜",
    implies: ["React"],
    html: /class="[^"]*ant-[a-z]+/i,
    patterns: [
      { type: "htmlSnippet", value: /class="[^"]*ant-[a-z]+/i }
    ]
  },

  // ─── CMS & ECOMMERCE ────────────────────────────────────────────────────────

  {
    name: "WordPress",
    category: "CMS",
    icon: "🔵",
    implies: ["PHP", "MySQL"],
    meta: { "generator": /wordpress\s+([\d.]+)/i },
    html: /\/wp-(?:content|includes)\//i,
    patterns: [
      { type: "htmlSnippet",  value: /\/wp-content\//i },
      { type: "htmlSnippet",  value: /\/wp-includes\//i },
      { type: "metaContent",  name: "generator", regex: /wordpress/i },
      { type: "scriptUrl",    value: /\/wp-content\// },
      { type: "linkUrl",      value: /\/wp-content\// },
    ],
    versionPatterns: [
      { type: "metaRegex",  metaName: "generator", regex: /wordpress\s+([\d.]+)/i, group: 1 },
      { type: "htmlRegex",  regex: /wp-emoji-release\.min\.js\?ver=([\d.]+)/i,     group: 1 },
      { type: "scriptUrlRegex", regex: /ver=([\d.]+)/i,                          group: 1 },
    ]
  },

  {
    name: "Shopify",
    category: "Ecommerce",
    icon: "🛍️",
    script: /cdn\.shopify\.com/i,
    html: /Shopify\.shop/i,
    patterns: [
      { type: "globalVar",   value: "Shopify" },
      { type: "scriptUrl",   value: /cdn\.shopify\.com/ },
      { type: "linkUrl",     value: /cdn\.shopify\.com/ },
      { type: "htmlSnippet", value: /Shopify\.shop/i },
    ],
    versionPatterns: [
      { type: "globalExpr", expr: "window.Shopify && window.Shopify.version" },
    ]
  },

  {
    name: "Magento",
    category: "Ecommerce",
    icon: "🛒",
    implies: ["PHP", "MySQL"],
    script: /mage\/cookies\.js/i,
    html: /var require = \{/i,
    patterns: [
      { type: "globalVar", value: "mage" },
      { type: "scriptUrl", value: /mage\/cookies\.js/i }
    ]
  },

  {
    name: "Drupal",
    category: "CMS",
    icon: "💧",
    implies: ["PHP"],
    meta: { "generator": /drupal/i },
    headers: { "x-generator": /drupal/i },
    patterns: [
      { type: "metaContent", name: "generator", regex: /drupal/i },
      { type: "globalVar", value: "Drupal" }
    ],
    versionPatterns: [
      { type: "metaRegex", metaName: "generator", regex: /drupal\s+([\d.]+)/i, group: 1 }
    ]
  },

  {
    name: "Joomla",
    category: "CMS",
    icon: "🌀",
    implies: ["PHP"],
    meta: { "generator": /joomla/i },
    patterns: [
      { type: "metaContent", name: "generator", regex: /joomla/i }
    ],
    versionPatterns: [
      { type: "metaRegex", metaName: "generator", regex: /joomla.*?([\d.]+)/i, group: 1 }
    ]
  },

  {
    name: "Wix",
    category: "CMS",
    icon: "✨",
    headers: { "x-wix-request-id": /.*/ },
    meta: { "generator": /wix\.com/i },
    patterns: [
      { type: "metaContent", name: "generator", regex: /wix\.com/i }
    ]
  },

  {
    name: "Squarespace",
    category: "CMS",
    icon: "⬛",
    script: /static\.squarespace\.com/i,
    patterns: [
      { type: "scriptUrl", value: /static\.squarespace\.com/i }
    ]
  },

  // ─── LIBRARIES ──────────────────────────────────────────────────────────────

  {
    name: "jQuery",
    category: "Libraries",
    icon: "📌",
    jsGlobals: { "jQuery.fn.jquery": "version" },
    script: /jquery(?:[-/]([\d.]+))?(?:\.min)?\.js/i,
    patterns: [
      { type: "globalVar",     value: "jQuery" },
      { type: "globalVar",     value: "$" },
      { type: "globalMethod",  value: "jQuery" },
      { type: "scriptUrl",     value: /jquery(?:\.min)?\.js/ },
    ],
    versionPatterns: [
      { type: "globalExpr",     expr: "window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery" },
      { type: "scriptUrlRegex", regex: /jquery[-/]([\d.]+)(?:\.min)?\.js/i, group: 1 },
      { type: "scriptUrlRegex", regex: /jquery[@/]([\d.]+)/i,               group: 1 },
    ]
  },

  {
    name: "Lodash",
    category: "Libraries",
    icon: "🛠️",
    script: /lodash(?:\.min)?\.js/i,
    patterns: [
      { type: "globalVar", value: "_" },
      { type: "scriptUrl", value: /lodash(?:\.min)?\.js/ }
    ],
    versionPatterns: [
      { type: "globalExpr", expr: "window._ && window._.VERSION" }
    ]
  },

  {
    name: "Moment.js",
    category: "Libraries",
    icon: "⏱️",
    script: /moment(?:\.min)?\.js/i,
    patterns: [
      { type: "globalVar", value: "moment" },
      { type: "scriptUrl", value: /moment(?:\.min)?\.js/ }
    ],
    versionPatterns: [
      { type: "globalExpr", expr: "window.moment && window.moment.version" }
    ]
  },

  {
    name: "D3.js",
    category: "Libraries",
    icon: "📈",
    script: /d3(?:\.v\d+)?(?:\.min)?\.js/i,
    patterns: [
      { type: "globalVar", value: "d3" },
      { type: "scriptUrl", value: /d3(?:\.v\d+)?(?:\.min)?\.js/ }
    ],
    versionPatterns: [
      { type: "globalExpr", expr: "window.d3 && window.d3.version" },
      { type: "scriptUrlRegex", regex: /d3\.v([\d.]+)(?:\.min)?\.js/i, group: 1 }
    ]
  },

  // ─── ANALYTICS ──────────────────────────────────────────────────────────────

  {
    name: "Google Analytics",
    category: "Analytics",
    icon: "📊",
    script: /(?:google-analytics\.com\/analytics\.js|googletagmanager\.com\/gtag\/js)/i,
    html: /(?:UA-\d{4,}-\d+|G-[A-Z0-9]{8,})/i,
    patterns: [
      { type: "globalVar",   value: "gtag" },
      { type: "globalVar",   value: "ga" },
      { type: "scriptUrl",   value: /google-analytics\.com\/analytics\.js/ },
      { type: "scriptUrl",   value: /googletagmanager\.com\/gtag\/js/ },
      { type: "htmlSnippet", value: /google-analytics\.com/i },
      { type: "htmlSnippet", value: /UA-\d{4,}-\d+/i },
      { type: "htmlSnippet", value: /G-[A-Z0-9]{8,}/i },
    ],
    versionPatterns: [
      { type: "htmlRegex", regex: /(G-[A-Z0-9]{8,})/i,    group: 1, label: "GA4" },
      { type: "htmlRegex", regex: /(UA-\d{4,}-\d+)/i,     group: 1, label: "Universal" },
    ]
  },

  {
    name: "Google Tag Manager",
    category: "Tag Manager",
    icon: "🏷️",
    script: /googletagmanager\.com\/gtm\.js/i,
    html: /GTM-[A-Z0-9]{4,}/i,
    patterns: [
      { type: "scriptUrl",   value: /googletagmanager\.com\/gtm\.js/ },
      { type: "htmlSnippet", value: /GTM-[A-Z0-9]{4,}/i },
      { type: "globalVar",   value: "google_tag_manager" },
    ],
    versionPatterns: [
      { type: "htmlRegex", regex: /(GTM-[A-Z0-9]{4,})/i, group: 1 },
    ]
  },

  {
    name: "Hotjar",
    category: "Analytics",
    icon: "🔥",
    script: /static\.hotjar\.com/i,
    patterns: [
      { type: "globalVar", value: "hj" },
      { type: "scriptUrl", value: /static\.hotjar\.com/ }
    ]
  },

  {
    name: "Mixpanel",
    category: "Analytics",
    icon: "📊",
    script: /cdn\.mxpnl\.com/i,
    patterns: [
      { type: "globalVar", value: "mixpanel" },
      { type: "scriptUrl", value: /cdn\.mxpnl\.com/ }
    ]
  },

  {
    name: "Segment",
    category: "Analytics",
    icon: "📊",
    script: /cdn\.segment\.com/i,
    patterns: [
      { type: "globalVar", value: "analytics" },
      { type: "scriptUrl", value: /cdn\.segment\.com/ }
    ]
  },

  {
    name: "Matomo",
    category: "Analytics",
    icon: "📊",
    script: /piwik\.js|matomo\.js/i,
    patterns: [
      { type: "globalVar", value: "Piwik" },
      { type: "globalVar", value: "Matomo" }
    ]
  },

  // ─── SERVER / LANGUAGE / DB ─────────────────────────────────────────────────

  {
    name: "Nginx",
    category: "Server",
    icon: "🟢",
    headers: { "server": /nginx/i },
    html: /<title>Welcome to nginx!<\/title>|nginx\//i,
    patterns: [
      { type: "metaContent",  name: "server",      regex: /nginx/i },
      { type: "htmlSnippet",  value: /<title>Welcome to nginx!<\/title>/i },
      { type: "htmlSnippet",  value: /nginx\//i },
    ],
    versionPatterns: [
      { type: "metaRegex",  metaName: "server", regex: /nginx\/([\d.]+)/i, group: 1 },
      { type: "htmlRegex",  regex: /nginx\/([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Apache",
    category: "Server",
    icon: "🪶",
    headers: { "server": /apache/i },
    html: /Apache\/[\d.]+|Apache Server at/i,
    patterns: [
      { type: "metaContent",  name: "server",   regex: /apache/i },
      { type: "htmlSnippet",  value: /Apache\/[\d.]+/i },
      { type: "htmlSnippet",  value: /Apache Server at/i },
    ],
    versionPatterns: [
      { type: "metaRegex", metaName: "server", regex: /Apache\/([\d.]+)/i, group: 1 },
      { type: "htmlRegex", regex: /Apache\/([\d.]+)/i, group: 1 },
    ]
  },

  {
    name: "Node.js",
    category: "Language",
    icon: "🟢",
    headers: { "x-powered-by": /node\.js|express/i },
    cookies: { "connect.sid": /.*/ },
    patterns: []
  },

  {
    name: "PHP",
    category: "Language",
    icon: "🐘",
    headers: { "x-powered-by": /php/i },
    cookies: { "PHPSESSID": /.*/ },
    patterns: [],
    versionPatterns: [
      { type: "htmlRegex", regex: /PHP\/([\d.]+)/i, group: 1 }
    ]
  },

  {
    name: "Python",
    category: "Language",
    icon: "🐍",
    headers: { "x-powered-by": /python/i },
    patterns: []
  },

  {
    name: "Express",
    category: "Server",
    icon: "🚂",
    implies: ["Node.js"],
    headers: { "x-powered-by": /express/i },
    patterns: []
  },

  {
    name: "Ruby",
    category: "Language",
    icon: "💎",
    headers: { "x-powered-by": /ruby|phusion passenger/i },
    patterns: []
  },

  {
    name: "Java",
    category: "Language",
    icon: "☕",
    headers: { "x-powered-by": /java|jsp|servlet/i },
    cookies: { "JSESSIONID": /.*/ },
    patterns: []
  },

  {
    name: "MySQL",
    category: "Database",
    icon: "🐬",
    patterns: []
  },

  {
    name: "PostgreSQL",
    category: "Database",
    icon: "🐘",
    patterns: []
  },

  {
    name: "MongoDB",
    category: "Database",
    icon: "🍃",
    patterns: []
  },

  {
    name: "Redis",
    category: "Database",
    icon: "🟥",
    patterns: []
  },

  // ─── CDN & SECURITY ─────────────────────────────────────────────────────────

  {
    name: "Cloudflare",
    category: "CDN",
    icon: "☁️",
    headers: { "server": /cloudflare/i },
    cookies: { "__cfduid": /.*/, "_cfuvid": /.*/ },
    script: /cloudflare\.com/i,
    html: /__cf_bm|cloudflare/i,
    patterns: [
      { type: "scriptUrl",   value: /cloudflare\.com/ },
      { type: "htmlSnippet", value: /__cf_bm/i },
      { type: "htmlSnippet", value: /cloudflare/i },
    ],
    versionPatterns: []
  },

  {
    name: "Fastly",
    category: "CDN",
    icon: "⚡",
    headers: { "x-fastly-request-id": /.*/, "via": /fastly/i },
    patterns: []
  },

  {
    name: "Amazon CloudFront",
    category: "CDN",
    icon: "☁️",
    headers: { "x-amz-cf-id": /.*/, "via": /cloudfront/i },
    patterns: []
  },

  {
    name: "Akamai",
    category: "CDN",
    icon: "🌐",
    headers: { "x-akamai-request-id": /.*/ },
    patterns: []
  },

  {
    name: "reCAPTCHA",
    category: "Security",
    icon: "🤖",
    script: /google\.com\/recaptcha/i,
    html: /g-recaptcha/i,
    patterns: [
      { type: "globalVar", value: "grecaptcha" },
      { type: "scriptUrl", value: /google\.com\/recaptcha/ }
    ]
  },

  {
    name: "hCaptcha",
    category: "Security",
    icon: "🛡️",
    script: /hcaptcha\.com\/1\/api\.js/i,
    html: /h-captcha/i,
    patterns: [
      { type: "globalVar", value: "hcaptcha" },
      { type: "scriptUrl", value: /hcaptcha\.com\/1\/api\.js/ }
    ]
  }

];
