import React from 'react';

const FEED_ITEMS = [
  'CVE-2024-21626 :: Microsoft Exchange :: DRS:94 :: ACTIVE EXPLOIT IN WILD',
  'CVE-2023-44487 :: Apache HTTP :: DRS:87 :: PoC PUBLISHED',
  'CVE-2024-3400 :: Palo Alto PAN-OS :: DRS:79 :: EXPLOIT CONFIRMED',
  'CVE-2023-23397 :: Microsoft Outlook :: DRS:71 :: PATCH AVAILABLE',
  'CVE-2024-0007 :: PAN-OS Panorama :: DRS:55 :: NO EXPLOIT KNOWN',
];

export default function LiveTicker({ items }) {
  const feed = items && items.length > 0 ? items : FEED_ITEMS;
  const text = feed.join('    ·    ');

  return (
    <div
      style={{
        height: 28,
        background: 'var(--surface)',
        borderTop: '1px solid var(--surface-border)',
        display: 'flex',
        alignItems: 'center',
        overflow: 'hidden',
        flexShrink: 0,
        gap: 12,
      }}
      role="marquee"
      aria-label="Live CVE intelligence feed"
    >
      {/* Label */}
      <div style={{
        padding: '0 10px',
        background: 'var(--primary)',
        color: '#000',
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: '0.1em',
        height: '100%',
        display: 'flex',
        alignItems: 'center',
        flexShrink: 0,
        whiteSpace: 'nowrap',
      }}>
        ▶ LIVE FEED
      </div>

      {/* Scrolling text */}
      <div style={{ flex: 1, overflow: 'hidden' }}>
        <div className="ticker-inner" style={{ fontSize: 11, color: 'var(--primary)', letterSpacing: '0.04em' }}>
          {text}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{text}
        </div>
      </div>
    </div>
  );
}
