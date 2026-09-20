import React, { useState, useEffect } from 'react';

function navTo(page) {
  window.dispatchEvent(new CustomEvent('bifrost:navigate', { detail: page }));
  if (window.__bifrost_navigate) window.__bifrost_navigate(page);
}

export default function DashboardPage() {
  const [lastDump, setLastDump] = useState(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem('bifrost_lastDump');
      if (raw) setLastDump(JSON.parse(raw));
    } catch {}
  }, []);

  const lastDumpLabel = lastDump ? `${lastDump.name || lastDump.engine || 'dump'}${lastDump.pid ? ` · pid ${lastDump.pid}` : ''}` : '— idle — no dumps yet';
  const lastDumpMeta = lastDump ? `engine ${lastDump.engine || '—'}${lastDump.ts ? ` · ${new Date(lastDump.ts).toLocaleString()}` : ''}` : 'run a dump from Engines → Dump';

  return (
    <>
      {/* garage header — matte dash with FM lime live dot */}
      <div style={{
        background: '#0a0a0c',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 5,
        padding: '11px 14px',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05), 0 0 10px rgba(126,255,63,0.06)',
        borderLeft: '3px solid #7EFF3F',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', flexShrink: 0 }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.14em', color: '#f8fafc', textTransform: 'uppercase', lineHeight: 1, fontWeight: 700 }}>BIFROST — GARAGE</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#64748b', letterSpacing: '0.06em', marginLeft: 6 }}>FM 89.7 · idle</span>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#7EFF3F', marginTop: 7, letterSpacing: '0.02em', lineHeight: 1.4, textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>
          Ready · 8 engines · bridge live — Toretto's bay
        </div>
      </div>

      {/* quick launch — 4 buttons, only first is primary */}
      <div className="page-config-card" style={{ padding: 12, marginTop: 12 }}>
        <div style={{ fontSize: 10, letterSpacing: '1.2px', textTransform: 'uppercase', color: '#f8fafc', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>Quick Launch</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginTop: 10 }}>
          {[
            { id: 'engines', label: 'Engines', sub: 'Workbench' },
            { id: 'processes', label: 'Processes', sub: 'Attach' },
            { id: 'dump', label: 'Dump', sub: 'Offsets' },
            { id: 'analyzer', label: 'Analyzer', sub: 'Rizin → Ghidra' },
          ].map((b, i) => (
            <button
              key={b.id}
              onClick={() => navTo(b.id)}
              className={i === 0 ? 'btn btn-primary' : 'btn btn-secondary'}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 2, padding: '10px 12px', textTransform: 'none', letterSpacing: '0', fontSize: 13 }}
            >
              <span style={{ fontWeight: 800, letterSpacing: '0.06em', textTransform: 'uppercase', fontSize: 12 }}>{b.label}</span>
              <span style={{ fontWeight: 500, opacity: 0.85, fontSize: 11, letterSpacing: '0.02em' }}>{b.sub}</span>
            </button>
          ))}
        </div>
      </div>

      {/* recent activity — inline */}
      <div className="page-config-card" style={{ padding: '12px 14px', marginTop: 12 }}>
        <div style={{ fontSize: 10, letterSpacing: '1.2px', textTransform: 'uppercase', color: '#f8fafc', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>Recent Activity</div>
        <div style={{ marginTop: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: '#f8fafc', lineHeight: 1.5, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {lastDumpLabel}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#64748b', marginTop: 2, lineHeight: 1.5 }}>
          {lastDumpMeta}
        </div>
        <div style={{ marginTop: 10, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,0.06)', fontFamily: 'var(--font-mono)', fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>
          Tip: <span style={{ color: '#a0a6ad' }}>⌘K</span> to jump · <span style={{ color: '#a0a6ad' }}>Ctrl+1..4</span> for Dashboard → Results
        </div>
      </div>

      <div style={{ marginTop: 12, fontFamily: 'var(--font-mono)', fontSize: 10, color: '#64748b', letterSpacing: '0.06em' }}>
        ⌘K for palette · Ctrl+1..4
      </div>

      <style>{`@media (max-width: 900px) { div[style*="repeat(4, 1fr)"] { grid-template-columns: 1fr 1fr !important; } }`}</style>
    </>
  );
}
