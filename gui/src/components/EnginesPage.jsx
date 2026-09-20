import React, { useState, useMemo, useCallback } from 'react';

const ENGINES = [
  {
    id: 'unreal',
    name: 'Unreal Engine',
    tag: 'UE4 / UE5',
    family: 'Unreal',
    desc: 'GObjects, GNames, GWorld pointer chains. Supports UE4.25+ and UE5.',
    module: 'engines.unreal.dumper.UnrealDumper',
    profile: 'UE5_DEFAULT',
    strategy: 'Pointer chains: GObjects / GNames / GWorld',
    chips: ['UE4.25+', 'UE5', 'Marvel Rivals auto-profile'],
  },
  {
    id: 'unity',
    name: 'Unity (Mono)',
    tag: 'MONO',
    family: 'Unity',
    desc: 'Assembly-CSharp metadata walking. Class hierarchy + field offsets via reflection data.',
    module: 'engines.unity.mono.MonoDumper',
    profile: '—',
    strategy: 'Assembly-CSharp metadata',
    chips: ['Mono', '.NET reflection'],
  },
  {
    id: 'unity_il2cpp',
    name: 'Unity (IL2CPP)',
    tag: 'IL2CPP',
    family: 'Unity',
    desc: 'Il2Cpp metadata parsing against libil2cpp globals. Full class/field dump from the binary.',
    module: 'engines.unity.il2cpp.IL2CPPDumper',
    profile: '—',
    strategy: 'Il2Cpp metadata + libil2cpp globals',
    chips: ['Global-metadata', 'libil2cpp'],
  },
  {
    id: 'source',
    name: 'Source Engine',
    tag: 'CS2 / TF2',
    family: 'Source',
    desc: 'Interface dumping, NetVar tables, ConVar scanning. Source 2 schema system.',
    module: 'engines.source.dumper.SourceDumper',
    profile: 'schema (Source 2)',
    strategy: 'SchemaSystem in schemasystem.dll',
    chips: ['CS2', 'NetVars', 'Schema2'],
  },
  {
    id: 'source_eac',
    name: 'Source (EAC)',
    tag: 'APEX r5',
    family: 'Source',
    desc: 'Modified Source engine (r5 branch). Player, weapon, glow structs. EAC-aware.',
    module: 'engines.source.dumper.SourceDumper',
    profile: 'r5 (same dumper, EAC attach path)',
    strategy: 'SchemaSystem (r5)',
    chips: ['Apex', 'EAC-aware'],
  },
  {
    id: 'blizzard',
    name: 'Blizzard ECS',
    tag: 'OW2',
    family: 'Other',
    desc: 'Entity-Component-System with RTTI scanning. Hero archetypes and view matrix.',
    module: 'engines.blizzard.dumper.BlizzardDumper',
    profile: '—',
    strategy: 'RTTI scanning / ECS',
    chips: ['OW2', 'RTTI'],
  },
  {
    id: 'custom',
    name: 'Custom / Generic',
    tag: 'AOB TOOL',
    family: 'Other',
    desc: 'Pattern-based scanning for any game. Define custom signatures and struct layouts.',
    module: 'not registry-backed',
    profile: '—',
    strategy: 'AOB signature patterns',
    chips: ['Sig-based'],
  },
];

const FAMILY_ORDER = ['Unreal', 'Unity', 'Source', 'Other'];

export default function EnginesPage({ selected, onSelect }) {
  const [q, setQ] = useState('');
  const selId = selected || ENGINES[0].id;

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return ENGINES;
    return ENGINES.filter(e =>
      `${e.name} ${e.tag} ${e.family} ${e.strategy} ${e.chips.join(' ')}`.toLowerCase().includes(needle)
    );
  }, [q]);

  const grouped = useMemo(() => {
    const g = {};
    FAMILY_ORDER.forEach(f => g[f] = []);
    filtered.forEach(e => (g[e.family] || (g[e.family] = [])).push(e));
    return g;
  }, [filtered]);

  // detail stale guard: if filtered empty, show placeholder not stale active
  const active = useMemo(() => {
    if (filtered.length === 0) return null;
    return ENGINES.find((e) => e.id === selId) && filtered.find(e => e.id === selId)
      ? ENGINES.find((e) => e.id === selId)
      : filtered[0];
  }, [selId, filtered]);
  const isTool = active?.id === 'custom';

  const copyWithToast = useCallback((text, label) => {
    if (window.bifrost?.copyWithToast) window.bifrost.copyWithToast(text, label);
    else if (window.bifrost?.toast) window.bifrost.toast(label || 'Copied', 'success');
    else if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
  }, []);

  const handleRailKeyDown = useCallback((e) => {
    if (filtered.length === 0) return;
    const idx = filtered.findIndex(en => en.id === (active?.id || filtered[0].id));
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const next = filtered[Math.min(idx + 1, filtered.length - 1)];
      if (next) onSelect(next.id);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const prev = filtered[Math.max(idx - 1, 0)];
      if (prev) onSelect(prev.id);
    }
  }, [filtered, active, onSelect]);

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Engine Workbench</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)', letterSpacing: '0.08em' }}>● SELECT  <span style={{ color: '#7EFF3F' }}>{active?.name?.toUpperCase() || 'IDLE'}</span></span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Pick a dumper, inspect its real configuration, then jump into the dump flow — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>⌘K to jump</span></div>
      </div>

      <div className="wb">
        <div className="wb-rail" role="listbox" aria-label="Engine list" tabIndex={0} onKeyDown={handleRailKeyDown}>
          <div className="search-bar" style={{ marginBottom: 10 }}>
            <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <input
              type="search"
              aria-label="Filter engines"
              autoComplete="off"
              placeholder="Filter engines…"
              value={q}
              onChange={e => setQ(e.target.value)}
            />
          </div>
          {FAMILY_ORDER.map(fam => {
            const list = grouped[fam];
            if (!list || list.length === 0) return null;
            return (
              <div key={fam} style={{ marginBottom: 8 }}>
                <div className="wb-fam">{fam}</div>
                {list.map((engine) => (
                  <button
                    key={engine.id}
                    role="option"
                    aria-selected={active?.id === engine.id}
                    aria-label={`${engine.name} ${engine.tag}`}
                    className={`wb-engine ${active?.id === engine.id ? 'selected' : ''}`}
                    onClick={() => onSelect(engine.id)}
                  >
                    <span className="tick" />
                    <span style={{ minWidth: 0 }}>
                      <div className="wb-ename">{engine.name}</div>
                      <div className="wb-etag">{engine.tag}</div>
                    </span>
                  </button>
                ))}
              </div>
            );
          })}
          {filtered.length === 0 && (
            <div className="empty-state">
              <div className="empty-title">No engines match "{q}"</div>
              <p className="empty-hint">Try "unreal" or "source"</p>
              <div className="empty-action"><button className="btn btn-secondary" onClick={() => setQ('')}>Clear filter</button></div>
            </div>
          )}
        </div>

        <div className="wb-detail">
          {!active ? (
            <div className="empty-state">
              <div className="empty-title">No engine selected</div>
              <p className="empty-hint">Clear the filter to browse all dumpers.</p>
              <div className="empty-action"><button className="btn btn-secondary" onClick={() => setQ('')}>Clear filter</button></div>
            </div>
          ) : (
            <>
              <div className="wb-dhead">
                <span className="wb-dname">{active.name}</span>
                <span className="engine-card-tag muted">
                  {active.tag}
                </span>
              </div>
              <p className="wb-ddesc">{active.desc}</p>

              <div className="wb-meta">
                <div className="wb-row">
                  <span className="k">Dumper module</span>
                  <span className="v" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ flex: 1, minWidth: 0 }}>{active.module}</span>
                    <button
                      className="btn"
                      style={{ padding: '2px 8px', fontSize: 10, flexShrink: 0 }}
                      onClick={() => copyWithToast(active.module, 'Dumper path copied')}
                      aria-label="Copy dumper module path"
                      title="Copy"
                    >
                      Copy
                    </button>
                  </span>
                </div>
                <div className="wb-row">
                  <span className="k">Schema profile</span>
                  <span className="v">{active.profile}</span>
                </div>
                <div className="wb-row">
                  <span className="k">Strategy</span>
                  <span className="v" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ flex: 1, minWidth: 0 }}>{active.strategy}</span>
                    <button
                      className="btn"
                      style={{ padding: '2px 8px', fontSize: 10, flexShrink: 0 }}
                      onClick={() => copyWithToast(active.strategy, 'Strategy copied')}
                      aria-label="Copy strategy"
                      title="Copy"
                    >
                      Copy
                    </button>
                  </span>
                </div>
              </div>

              <div className="wb-caps">
                {active.chips.map((c) => (
                  <span key={c} className="wb-cap">{c}</span>
                ))}
              </div>

              <div className="wb-cta" style={{ flexWrap: 'wrap' }}>
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    onSelect(active.id);
                    // explicit navigation — replaces the old rail-click auto-nav
                    try {
                      window.dispatchEvent(new CustomEvent('bifrost:navigate', { detail: 'processes' }));
                    } catch {}
                    // also try direct prop navigation if parent exposed it via window
                    if (window.__bifrost_navigate) window.__bifrost_navigate('processes');
                  }}
                  disabled={!active}
                  title="Select engine and go to process attach"
                >
                  {isTool ? 'Open Pattern Flow' : 'Use this Engine — Go to Processes'}
                </button>
                <button
                  className="btn"
                  onClick={() => copyWithToast(active.name, 'Engine name copied')}
                  title="Copy engine name"
                >
                  Copy Engine Name
                </button>
                <span className="hint">
                  {isTool
                    ? 'Signature-driven flow, not a registry dumper. Rail click only selects.'
                    : 'Rail click only selects — use the red button to attach.'}
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}
