import React, { useState } from 'react';

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

  const api = window.bifrost;

  const loadFile = async (setter, nameSetter) => {
    // Use Electron native dialog if available
    if (api?.loadJsonFile) {
      try {
        const result = await api.loadJsonFile();
        if (result && result.data) {
          setter(result.data);
          nameSetter(result.filename || 'loaded');
          return;
        }
        if (result?.cancelled) return;
      } catch {}
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
        try { setter(JSON.parse(ev.target.result)); } catch {}
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
      <div className="page-header">
        <div className="page-title">Offset Diff Viewer</div>
        <div className="page-subtitle">Compare two dumps to find what changed after a game update</div>
      </div>

      <div className="diff-toolbar">
        <button className="btn" onClick={() => loadFile(setBefore, setBeforeName)}>
          {beforeName ? `Before: ${beforeName}` : 'Load Before'}
        </button>
        <span style={{ color: 'var(--text-muted)' }}>vs</span>
        <button className="btn" onClick={() => loadFile(setAfter, setAfterName)}>
          {afterName ? `After: ${afterName}` : 'Load After'}
        </button>
        <div style={{ flex: 1 }} />
        {total > 0 && (
          <select
            className="input-field"
            style={{ width: 160 }}
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
        <div className="diff-summary">
          <div className="diff-stat">
            <span className="dot added" />
            <span style={{ color: 'var(--success)' }}>{diff.added.length} added</span>
          </div>
          <div className="diff-stat">
            <span className="dot removed" />
            <span style={{ color: 'var(--error)' }}>{diff.removed.length} removed</span>
          </div>
          <div className="diff-stat">
            <span className="dot changed" />
            <span style={{ color: 'var(--warn)' }}>{diff.changed.length} changed</span>
          </div>
          <div className="diff-stat">
            <span className="dot unchanged" />
            <span style={{ color: 'var(--text-muted)' }}>{diff.unchanged.length} unchanged</span>
          </div>
        </div>
      )}

      {!before && !after ? (
        <div className="log-console" style={{ textAlign: 'center', padding: 40 }}>
          <p className="log-line dim">Load two JSON dump files to compare offsets.</p>
          <p className="log-line dim" style={{ marginTop: 8, fontSize: 11 }}>
            Tip: Dump a game before an update, save the JSON. After the update, dump again and compare.
          </p>
        </div>
      ) : total === 0 && before && after ? (
        <div className="log-console" style={{ textAlign: 'center', padding: 40 }}>
          <p className="log-line success">No differences found. Both dumps are identical.</p>
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
                    <span style={{ color: 'var(--accent)' }}>
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
