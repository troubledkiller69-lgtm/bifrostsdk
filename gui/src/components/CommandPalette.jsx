import React, { useState, useEffect, useMemo, useRef } from 'react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', keys: ['dashboard', 'home', 'system'], action: 'nav' },
  { id: 'engines', label: 'Engines', keys: ['engine', 'workbench'], action: 'nav' },
  { id: 'processes', label: 'Processes', keys: ['process', 'attach', 'pid'], action: 'nav' },
  { id: 'dump', label: 'Dump', keys: ['dump', 'scan', 'offsets'], action: 'nav' },
  { id: 'results', label: 'Results', keys: ['results', 'fields', 'headers'], action: 'nav' },
  { id: 'diff', label: 'Diff Viewer', keys: ['diff', 'compare'], action: 'nav' },
  { id: 'memory', label: 'Memory Viewer', keys: ['memory', 'hex', 'read'], action: 'nav' },
  { id: 'acmonitor', label: 'AC Monitor', keys: ['ac', 'anticheat', 'eac'], action: 'nav' },
  { id: 'analyzer', label: 'Analyzer', keys: ['analyzer', 'decompile', 'rizin', 'ghidra'], action: 'nav' },
  { id: 'diag', label: 'Diagnostics', keys: ['diag', 'telemetry', 'threads'], action: 'nav' },
  { id: 'driverbay', label: 'Driver Bay', keys: ['driver', 'byo', 'vulnerable', 'physmem'], action: 'nav' },
  { id: 'config', label: 'Config Editor', keys: ['config', 'offsets', 'patterns'], action: 'nav' },
  { id: 'settings', label: 'Settings', keys: ['settings', 'theme', 'webhook'], action: 'nav' },
];

const ACTIONS = [
  { id: 'act-start-dump', label: 'Start Dump', keys: ['start', 'dump'], action: 'fn', fn: 'startDump' },
  { id: 'act-refresh-proc', label: 'Refresh Processes', keys: ['refresh'], action: 'fn', fn: 'refreshProc' },
  { id: 'act-toggle-theme', label: 'Toggle Theme', keys: ['theme', 'midnight', 'paper'], action: 'fn', fn: 'toggleTheme' },
  { id: 'act-copy-cpp', label: 'Copy C++ Header (Results)', keys: ['copy', 'cpp'], action: 'fn', fn: 'copyCpp' },
];

function fuzzyScore(query, text) {
  if (!query) return 1;
  const q = query.toLowerCase().trim();
  const t = text.toLowerCase();
  if (!q) return 1;
  if (t.includes(q)) {
    // exact substring — boost if it starts at word boundary
    const idx = t.indexOf(q);
    const boundary = idx === 0 || /[\s\/_-]/.test(t[idx - 1]);
    return boundary ? 3 : 2.5;
  }
  // subsequence with consecutive bonus + early-match bonus
  let qi = 0, score = 0, consecutive = 0, lastIdx = -2;
  for (let i = 0; i < t.length && qi < q.length; i++) {
    if (t[i] === q[qi]) {
      const isConsecutive = i === lastIdx + 1;
      consecutive = isConsecutive ? consecutive + 1 : 1;
      // early in string = higher
      const posBonus = Math.max(0, 8 - i * 0.3);
      const runBonus = consecutive * 0.4;
      score += 1 + posBonus + runBonus;
      lastIdx = i;
      qi++;
    }
  }
  if (qi !== q.length) return 0;
  // length penalty — shorter haystack is tighter match
  const lenPenalty = t.length * 0.02;
  return Math.max(0.6, score - lenPenalty);
}

export default function CommandPalette({ open, setOpen, onNavigate, onAction }) {
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const inputRef = useRef(null);
  const triggerRef = useRef(null);

  useEffect(() => {
    if (open) {
      triggerRef.current = document.activeElement;
      setQ('');
      setSel(0);
      setTimeout(() => inputRef.current?.focus(), 10);
    } else {
      // return focus to trigger on close
      if (triggerRef.current && typeof triggerRef.current.focus === 'function') {
        setTimeout(() => triggerRef.current?.focus(), 10);
      }
    }
  }, [open]);

  const items = useMemo(() => {
    const all = [...NAV_ITEMS, ...ACTIONS];
    if (!q.trim()) return all.slice(0, 12);
    const scored = all.map(it => {
      const hay = `${it.label} ${it.id} ${(it.keys || []).join(' ')}`;
      // label gets 1.4x weight — navigation intent
      const labelScore = fuzzyScore(q, it.label) * 1.4;
      const hayScore = fuzzyScore(q, hay);
      return { it, score: Math.max(labelScore, hayScore) };
    }).filter(x => x.score > 0);
    scored.sort((a, b) => b.score - a.score || a.it.label.localeCompare(b.it.label));
    return scored.slice(0, 12).map(x => x.it);
  }, [q]);

  useEffect(() => setSel(0), [q]);

  const exec = (item) => {
    if (!item) return;
    if (item.action === 'nav') onNavigate(item.id);
    else if (item.action === 'fn') onAction(item.fn);
    setOpen(false);
  };

  if (!open) return null;

  return (
    <div className="cmdk-overlay" role="dialog" aria-modal="true" aria-label="Command palette" onClick={() => setOpen(false)}>
      <div className="cmdk-panel" onClick={e => e.stopPropagation()}>
        <div className="cmdk-input-row">
          <span className="cmdk-icon">⌘</span>
          <input
            ref={inputRef}
            className="cmdk-input"
            placeholder="Jump to… (engines, dump, hex)"
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(s + 1, items.length - 1)); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(s - 1, 0)); }
              else if (e.key === 'Enter') { e.preventDefault(); exec(items[sel]); }
              else if (e.key === 'Escape') setOpen(false);
            }}
          />
          <span className="cmdk-hint">ESC</span>
        </div>
        <div className="cmdk-list" role="listbox" aria-label="Commands">
          {items.length === 0 ? (
            <div className="cmdk-empty">No match — try “dump” or “hex” · {q.length} chars</div>
          ) : items.map((it, i) => (
            <div
              key={it.id}
              role="option"
              aria-selected={i === sel}
              id={`cmdk-opt-${it.id}`}
              className={`cmdk-item ${i === sel ? 'active' : ''}`}
              onClick={() => exec(it)}
              onMouseEnter={() => setSel(i)}
            >
              <span className="cmdk-label">{it.label}</span>
              <span className="cmdk-meta">{it.action === 'nav' ? 'Go to' : 'Action'} · {it.id} · {it.keys?.slice(0,2).join(' ')}</span>
            </div>
          ))}
        </div>
        <div className="cmdk-footer">
          <span>↑↓ Navigate · ↵ Select · ⌘K Toggle</span>
          <span className="dim">Linear-style palette</span>
        </div>
      </div>
    </div>
  );
}
