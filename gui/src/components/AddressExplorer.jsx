import React, { useState } from 'react';

function fmtAddr(addr) {
  return '0x' + addr.toString(16).toUpperCase();
}

function parseAddr(text) {
  const t = String(text || '').trim();
  if (!t) return null;
  const n = /^0x/i.test(t) ? parseInt(t, 16) : parseInt(t, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function unwrapPayload(res) {
  return res && res.type === 'result' ? res.data : res;
}

export default function AddressExplorer({ api, enabled, sessionOpen }) {
  const [addrText, setAddrText] = useState('');
  const [busy, setBusy] = useState(false);
  const [current, setCurrent] = useState(null); // {addr}
  const [hexdump, setHexdump] = useState(null);
  const [disasm, setDisasm] = useState(null);
  const [xrefs, setXrefs] = useState(null);
  const [err, setErr] = useState('');
  const [view, setView] = useState('hex'); // hex | disasm | xrefs

  const load = async (addr, showView) => {
    if (!api) return;
    setErr('');
    setBusy(true);
    setCurrent({ addr });
    if (showView) setView(showView);
    const [h, d, x] = await Promise.allSettled([
      api.analyzerHexdump(addr, 256),
      api.analyzerDisasmAt(addr, 160),
      api.analyzerXrefs(addr),
    ]);
    setBusy(false);

    const pick = (settled) => {
      if (settled.status !== 'fulfilled') {
        return { error: settled.reason?.message || String(settled.reason) };
      }
      return unwrapPayload(settled.value) || {};
    };
    const hd = pick(h);
    const dd = pick(d);
    const xd = pick(x);
    setHexdump(hd.rows ? hd : null);
    setDisasm(dd.lines ? dd : null);
    setXrefs(Array.isArray(xd.xrefs) ? xd : null);
    const firstErr = [hd, dd, xd].find((r) => r && r.error);
    setErr(firstErr ? `${firstErr.code || 'ERROR'}: ${firstErr.error}` : '');
  };

  const onGo = () => {
    const addr = parseAddr(addrText);
    if (!addr) { setErr('Enter a hex (0x...) or decimal address'); return; }
    load(addr, 'hex');
  };

  const jump = (addr) => {
    setAddrText(fmtAddr(addr));
    load(addr, 'hex');
  };

  const followAsm = (addr) => {
    setAddrText(fmtAddr(addr));
    load(addr, 'hex');
  };

  if (!enabled) {
    return (
      <div className="hunter-config-card" style={{ padding: 14 }}>
        <div className="hunter-config-title">Address Explorer</div>
        <div className="log-line dim" style={{ fontSize: 12 }}>
          {sessionOpen
            ? 'Run an analyze job first, then explore any address in the image.'
            : 'Analyze a binary to unlock the address explorer (hex, disasm, xrefs).'}
        </div>
      </div>
    );
  }

  return (
    <div className="hunter-config-card" style={{ padding: 14 }}>
      <div className="hunter-config-title" style={{ marginBottom: 10 }}>
        Address Explorer
        {current && (
          <span style={{ marginLeft: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
            {fmtAddr(current.addr)}
          </span>
        )}
        {busy && (
          <span style={{ marginLeft: 10, color: 'var(--frost-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
            scanning...
          </span>
        )}
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
        <input
          type="text"
          className="input-field"
          style={{ fontFamily: 'var(--font-mono)', flex: 1 }}
          placeholder="0x180001000"
          value={addrText}
          spellCheck={false}
          onChange={(e) => setAddrText(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') onGo(); }}
        />
        <button className="btn btn-secondary" onClick={onGo} disabled={busy}>
          Go
        </button>
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        {[
          ['hex', 'Hex'],
          ['disasm', 'Disasm'],
          ['xrefs', 'Xrefs'],
        ].map(([key, label]) => (
          <button
            key={key}
            className={`btn ${view === key ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '4px 12px', fontSize: 11 }}
            onClick={() => setView(key)}
          >
            {label}
          </button>
        ))}
        {current && (
          <button
            className="btn btn-secondary"
            style={{ padding: '4px 12px', fontSize: 11 }}
            onClick={() => load(current.addr, view)}
            disabled={busy}
          >
            Refresh
          </button>
        )}
      </div>

      {err && (
        <div style={{ color: 'var(--error)', fontSize: 11, marginBottom: 8 }}>
          {err}
        </div>
      )}

      {view === 'hex' && (
        hexdump ? (
          <div className="log-console" style={{ maxHeight: 320, overflow: 'auto', padding: '8px 0' }}>
            {hexdump.rows.map((row) => (
              <div key={row.addr} className="hex-row" title={fmtAddr(row.addr)}>
                <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {fmtAddr(row.addr)}
                </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11, flex: 1, padding: '0 10px' }}>
                  {row.hex}
                </span>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {row.ascii}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="log-line dim" style={{ fontSize: 12 }}>No dump for this address yet — hit Go.</div>
        )
      )}

      {view === 'disasm' && (
        disasm ? (
          <div className="log-console" style={{ maxHeight: 320, overflow: 'auto', padding: '8px 0' }}>
            <div className="log-line dim" style={{ fontSize: 10, padding: '0 8px 4px', fontFamily: 'var(--font-mono)' }}>
              arch: {disasm.arch} — click an address to follow it
            </div>
            {disasm.lines.map((line, i) => (
              <div
                key={i}
                className="hex-row asm-row"
                onClick={() => followAsm(line.address)}
                title="Follow this address"
              >
                <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {fmtAddr(line.address)}
                </span>
                <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '0 10px', flexShrink: 0 }}>
                  {line.bytes}
                </span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {line.text}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="log-line dim" style={{ fontSize: 12 }}>No disassembly yet — hit Go.</div>
        )
      )}

      {view === 'xrefs' && (
        xrefs ? (
          xrefs.xrefs.length === 0 ? (
            <div className="log-line dim" style={{ fontSize: 12 }}>
              No references to this address{!xrefs._rizin ? ' (xrefs need the rizin engine)' : ''}.
            </div>
          ) : (
            <div className="log-console" style={{ maxHeight: 320, overflow: 'auto', padding: '8px 0' }}>
              {xrefs.xrefs.map((x, i) => (
                <div key={i} className="hex-row xref-row" onClick={() => jump(x.from)} title="Jump to source">
                  <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    {fmtAddr(x.from)}
                  </span>
                  <span style={{ color: 'var(--warn)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '0 10px' }}>
                    {x.type}
                  </span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {x.op}
                  </span>
                </div>
              ))}
            </div>
          )
        ) : (
          <div className="log-line dim" style={{ fontSize: 12 }}>No xrefs yet — hit Go.</div>
        )
      )}
    </div>
  );
}
