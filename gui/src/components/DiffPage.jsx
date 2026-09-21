import React, { useState, useContext, useEffect } from 'react';
import { ToastContext } from '../App';

function computeDiff(before, after) {
  if (!before || !after) return { added: [], removed: [], changed: [], unchanged: [] };

  const beforeMap = {};
  (before.classes || []).forEach(cls => {
    (cls.fields || []).forEach(f => {
      beforeMap[`${cls.name}::${f.name}`] = { ...f, className: cls.name };
    });
  });

  const afterMap = {};
  (after.classes || []).forEach(cls => {
    (cls.fields || []).forEach(f => {
      afterMap[`${cls.name}::${f.name}`] = { ...f, className: cls.name };
    });
  });

  const added = [], removed = [], changed = [], unchanged = [];

  Object.keys(afterMap).forEach(key => {
    const a = afterMap[key];
    if (!beforeMap[key]) {
      added.push(a);
    } else {
      const b = beforeMap[key];
      if (b.offset !== a.offset || b.type !== a.type || b.size !== a.size) {
        changed.push({ ...a, oldOffset: b.offset, oldType: b.type, oldSize: b.size });
      } else {
        unchanged.push(a);
      }
    }
  });

  Object.keys(beforeMap).forEach(key => {
    if (!afterMap[key]) {
      removed.push(beforeMap[key]);
    }
  });

  return { added, removed, changed, unchanged };
}

export default function DiffPage() {
  const [before, setBefore] = useState(null);
  const [after, setAfter] = useState(null);
  const [beforeName, setBeforeName] = useState('');
  const [afterName, setAfterName] = useState('');
  const [filter, setFilter] = useState('all');
  const [parseError, setParseError] = useState('');
  const toast = useContext(ToastContext);

  const api = window.bifrost;

  // History mode — every successful dump auto-archives into
  // output/<game>/.history/. Pick two snapshots, diff server-side.
  const [history, setHistory] = useState(null);
  const [histGame, setHistGame] = useState('');
  const [histBefore, setHistBefore] = useState('');
  const [histAfter, setHistAfter] = useState('');
  const [histDiff, setHistDiff] = useState(null);
  const [histBusy, setHistBusy] = useState(false);
  const [histError, setHistError] = useState('');

  useEffect(() => {
    if (!api?.dumpHistory) return;
    api.dumpHistory()
      .then((r) => {
        const p = r?.type === 'result' ? r.data : r;
        if (p && !p.error) {
          setHistory(p.games || {});
          const games = Object.keys(p.games || {});
          if (games.length === 1) setHistGame(games[0]);
        }
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const histEntries = histGame && history ? (history[histGame] || []) : [];

  const runHistDiff = async () => {
    if (!api?.dumpDiff || !histBefore || !histAfter) return;
    setHistBusy(true);
    setHistError('');
    setHistDiff(null);
    try {
      const r = await api.dumpDiff(histBefore, histAfter);
      const p = r?.type === 'result' ? r.data : r;
      if (p?.error) setHistError(p.code ? `${p.code}: ${p.error}` : p.error);
      else setHistDiff(p);
    } catch (e) {
      setHistError(e?.message || String(e));
    }
    setHistBusy(false);
  };

  const showToast = (msg, type = 'error') => {
    if (window.bifrost?.toast) window.bifrost.toast(msg, type);
    else if (toast) toast(msg, type);
  };

  const validateDump = (data) => {
    if (!data || !Array.isArray(data.classes)) {
      showToast('Invalid dump file: expected { classes: [...] }', 'error');
      setParseError('Invalid dump file: missing classes array');
      return false;
    }
    return true;
  };

  const loadFile = async (setter, nameSetter) => {
    setParseError('');
    // Use Electron native dialog if available
    if (api?.loadJsonFile) {
      try {
        const result = await api.loadJsonFile();
        if (result && result.data) {
          if (!validateDump(result.data)) return;
          setter(result.data);
          nameSetter(result.filename || 'loaded');
          return;
        }
        if (result?.cancelled) return;
      } catch (e) {
        showToast('Invalid dump file', 'error');
        setParseError('Invalid dump file');
        return;
      }
    }

    // Dev fallback: browser file input
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (!file) return;
      nameSetter(file.name);
      const reader = new FileReader();
      reader.onload = (ev) => {
        try {
          const parsed = JSON.parse(ev.target.result);
          if (!validateDump(parsed)) return;
          setter(parsed);
        } catch {
          showToast('Invalid dump file', 'error');
          setParseError('Invalid dump file');
        }
      };
      reader.readAsText(file);
    };
    input.click();
  };

  const diff = computeDiff(before, after);
  const total = diff.added.length + diff.removed.length + diff.changed.length + diff.unchanged.length;

  const getVisibleRows = () => {
    switch (filter) {
      case 'added': return diff.added.map(r => ({ ...r, status: 'added' }));
      case 'removed': return diff.removed.map(r => ({ ...r, status: 'removed' }));
      case 'changed': return diff.changed.map(r => ({ ...r, status: 'changed' }));
      default:
        return [
          ...diff.added.map(r => ({ ...r, status: 'added' })),
          ...diff.removed.map(r => ({ ...r, status: 'removed' })),
          ...diff.changed.map(r => ({ ...r, status: 'changed' })),
          ...diff.unchanged.map(r => ({ ...r, status: 'unchanged' })),
        ];
    }
  };

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Offset Diff</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: total ? '#7EFF3F' : 'var(--text-ghost)', letterSpacing: '0.08em' }}>● {total ? `${diff.changed.length} MOD · ${diff.added.length} NEW · ${diff.removed.length} DEL` : 'NO DIFF'}</span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Compare two dumps to find what changed after a game update — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>BEFORE vs AFTER · lime NEW · rose DEL · steel MOD</span></div>
      </div>

      {parseError && (
        <div role="alert" style={{ background: 'var(--error-soft)', border: '1px solid rgba(217,74,74,0.22)', borderRadius: 5, padding: '8px 12px', marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--error)' }}>
          {parseError}
        </div>
      )}

      {(history && Object.keys(history).length > 0) && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 5, background: '#0a0a0c', border: '1px solid rgba(126,255,63,0.18)', borderTop: '1px solid rgba(126,255,63,0.28)', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.08)' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>History</span>
          <select className="input-field" style={{ fontSize: 12, minWidth: 140 }} value={histGame} onChange={(e) => { setHistGame(e.target.value); setHistBefore(''); setHistAfter(''); setHistDiff(null); }}>
            <option value="">Game…</option>
            {Object.keys(history).map((g) => <option key={g} value={g}>{g} ({history[g].length})</option>)}
          </select>
          <select className="input-field" style={{ fontSize: 12, minWidth: 170 }} value={histBefore} onChange={(e) => setHistBefore(e.target.value)} disabled={!histGame}>
            <option value="">Before…</option>
            {histEntries.map((en) => <option key={en.stamp} value={en.path}>{en.stamp} · {en.classes}c/{en.fields}f</option>)}
          </select>
          <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>vs</span>
          <select className="input-field" style={{ fontSize: 12, minWidth: 170 }} value={histAfter} onChange={(e) => setHistAfter(e.target.value)} disabled={!histGame}>
            <option value="">After…</option>
            {histEntries.map((en) => <option key={en.stamp} value={en.path}>{en.stamp} · {en.classes}c/{en.fields}f</option>)}
          </select>
          <button className="btn btn-primary" style={{ fontSize: 11, padding: '6px 14px' }} onClick={runHistDiff} disabled={!histBefore || !histAfter || histBusy}>{histBusy ? 'DIFFING…' : 'Compare'}</button>
        </div>
      )}
      {histError && (
        <div role="alert" style={{ background: 'var(--error-soft)', border: '1px solid rgba(217,74,74,0.22)', borderRadius: 5, padding: '8px 12px', marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--error)' }}>
          {histError}
        </div>
      )}
      {histDiff && (
        <div style={{ background: '#0a0a0c', border: `1px solid ${histDiff.drift ? 'rgba(217,74,74,0.25)' : 'rgba(126,255,63,0.22)'}`, borderRadius: 5, padding: '10px 12px', marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: histDiff.drift ? 8 : 0 }}>
            <span style={{ color: histDiff.drift ? '#d94a4a' : '#7EFF3F', fontWeight: 700 }}>{histDiff.drift ? `DRIFT: ${histDiff.changed_fields} changed fields` : 'NO DRIFT'}</span>
            <span style={{ color: 'var(--text-muted)' }}>{Object.keys(histDiff.changed || {}).length} mod classes</span>
            <span style={{ color: '#7EFF3F' }}>+{(histDiff.added || []).length} new</span>
            <span style={{ color: '#d94a4a' }}>−{(histDiff.removed || []).length} del</span>
            <span style={{ color: 'var(--text-ghost)' }}>{histDiff.unchanged_count} ok</span>
          </div>
          {(histDiff.removed || []).length > 0 && (
            <div style={{ marginTop: 6 }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: '#d94a4a', marginBottom: 4 }}>Removed classes</div>
              {(histDiff.removed || []).slice(0, 30).map((n) => <div key={n} style={{ color: '#d94a4a' }}>− {n}</div>)}
            </div>
          )}
          {(histDiff.added || []).length > 0 && (
            <div style={{ marginTop: 6 }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: '#7EFF3F', marginBottom: 4 }}>New classes</div>
              {(histDiff.added || []).slice(0, 30).map((n) => <div key={n} style={{ color: '#7EFF3F' }}>+ {n}</div>)}
            </div>
          )}
          {Object.keys(histDiff.changed || {}).length > 0 && (
            <div style={{ marginTop: 6, maxHeight: 320, overflow: 'auto' }}>
              <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 1, color: '#94a3b8', marginBottom: 4 }}>Changed</div>
              {Object.keys(histDiff.changed).sort().slice(0, 60).map((cls) => (
                <div key={cls} style={{ marginBottom: 6 }}>
                  <div style={{ color: '#f8fafc', fontWeight: 700 }}>~ {cls}</div>
                  {(histDiff.changed[cls] || []).slice(0, 20).map((line, i) => (
                    <div key={i} style={{ color: 'var(--text-secondary)', paddingLeft: 12 }}>{line}</div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="diff-toolbar">
        <button className="btn" onClick={() => loadFile(setBefore, setBeforeName)} style={{ fontSize: 12 }}>
          {beforeName ? `Before: ${beforeName}` : 'Load Before'}
        </button>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>vs</span>
        <button className="btn" onClick={() => loadFile(setAfter, setAfterName)} style={{ fontSize: 12 }}>
          {afterName ? `After: ${afterName}` : 'Load After'}
        </button>
        <div style={{ flex: 1 }} />
        {total > 0 && (
          <select
            className="input-field"
            style={{ width: 160, fontSize: 12 }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="all">All ({total})</option>
            <option value="added">Added ({diff.added.length})</option>
            <option value="removed">Removed ({diff.removed.length})</option>
            <option value="changed">Changed ({diff.changed.length})</option>
          </select>
        )}
      </div>

      {total > 0 && (
        <div className="diff-summary" style={{ background: '#0a0a0c', border: '1px solid rgba(255,255,255,0.08)', borderTop: '1px solid rgba(255,255,255,0.12)', borderRadius: 5, padding: '10px 12px', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.08)', marginBottom: 12 }}>
          <div className="diff-stat">
            <span className="dot added" style={{ background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)' }} />
            <span style={{ color: '#7EFF3F', fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: 11, textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>{diff.added.length} NEW</span>
          </div>
          <div className="diff-stat">
            <span className="dot removed" style={{ background: '#d94a4a' }} />
            <span style={{ color: '#d94a4a', fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: 11 }}>{diff.removed.length} DEL</span>
          </div>
          <div className="diff-stat">
            <span className="dot changed" style={{ background: '#94a3b8' }} />
            <span style={{ color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: 11 }}>{diff.changed.length} MOD</span>
          </div>
          <div className="diff-stat">
            <span className="dot unchanged" style={{ background: 'var(--text-ghost)' }} />
            <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{diff.unchanged.length} OK</span>
          </div>
          <div style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)' }}>{total} fields</div>
        </div>
      )}

      {!before && !after ? (
        <div className="empty-state" style={{ padding: 36 }}>
          <div className="empty-title">No dumps loaded</div>
          <p className="empty-hint">Load two JSON dump files to compare offsets.</p>
          <div className="empty-action" style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 8 }}>
            <button className="btn btn-primary" onClick={() => loadFile(setBefore, setBeforeName)}>Load Before</button>
            <button className="btn btn-primary" onClick={() => loadFile(setAfter, setAfterName)}>Load After</button>
          </div>
          <p className="empty-hint" style={{ marginTop: 8, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-ghost)' }}>
            Tip: Dump before an update, save JSON. After update, dump again and compare.
          </p>
        </div>
      ) : total === 0 && before && after ? (
        <div className="empty-state" style={{ padding: 36 }}>
          <p className="log-line success" style={{ fontWeight: 600 }}>No differences found. Both dumps are identical.</p>
        </div>
      ) : (
        <div className="field-table-wrapper" style={{ maxHeight: 'calc(100vh - 320px)' }}>
          <table className="diff-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Class</th>
                <th>Field</th>
                <th>Offset</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {getVisibleRows().map((row, i) => (
                <tr key={i} className={`diff-row-${row.status}`}>
                  <td style={{ width: 80 }}>
                    <span style={{
                      fontSize: 9,
                      textTransform: 'uppercase',
                      letterSpacing: 0.5,
                      fontWeight: 700,
                    }}>
                      {row.status === 'added' ? '+ NEW' :
                       row.status === 'removed' ? '- DEL' :
                       row.status === 'changed' ? '~ MOD' : '= OK'}
                    </span>
                  </td>
                  <td>{row.className}</td>
                  <td style={{ fontWeight: 500 }}>{row.name}</td>
                  <td>
                    {row.status === 'changed' && row.oldOffset !== row.offset && (
                      <span className="diff-old-value">0x{row.oldOffset?.toString(16).toUpperCase()}</span>
                    )}
                    <span style={{ color: row.status === 'added' ? '#7EFF3F' : row.status === 'removed' ? 'var(--error)' : 'var(--accent)', fontWeight: 600 }}>
                      0x{(row.offset || 0).toString(16).toUpperCase()}
                    </span>
                  </td>
                  <td>
                    {row.status === 'changed' && row.oldType !== row.type && (
                      <span className="diff-old-value">{row.oldType}</span>
                    )}
                    {row.type || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
