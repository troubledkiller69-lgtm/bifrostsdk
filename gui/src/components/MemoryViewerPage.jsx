import React, { useState, useEffect, useRef, useCallback } from 'react';

function toHex(byte) {
  return byte.toString(16).toUpperCase().padStart(2, '0');
}

function toAscii(byte) {
  return byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
}

function parseHexInput(input) {
  const cleaned = input.trim().replace(/^0x/i, '');
  return parseInt(cleaned, 16);
}

function fmtAddr(n) { return '0x' + Number(n).toString(16).toUpperCase(); }

function interpretBytes(bytes, offset) {
  if (!bytes || bytes.length === 0) return {};
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  for (let i = 0; i < Math.min(bytes.length, 8); i++) {
    view.setUint8(i, bytes[i]);
  }
  return {
    int8: bytes[0] !== undefined ? (bytes[0] > 127 ? bytes[0] - 256 : bytes[0]) : '-',
    uint8: bytes[0] !== undefined ? bytes[0] : '-',
    int16: bytes.length >= 2 ? view.getInt16(0, true) : '-',
    uint16: bytes.length >= 2 ? view.getUint16(0, true) : '-',
    int32: bytes.length >= 4 ? view.getInt32(0, true) : '-',
    uint32: bytes.length >= 4 ? view.getUint32(0, true) : '-',
    float: bytes.length >= 4 ? view.getFloat32(0, true).toFixed(6) : '-',
    double: bytes.length >= 8 ? view.getFloat64(0, true).toFixed(6) : '-',
    hex: bytes.map(b => toHex(b)).join(' '),
    ascii: bytes.map(b => toAscii(b)).join(''),
    ptr64: bytes.length >= 8 ? (()=>{ let v=0n; for(let i=7;i>=0;i--) v=(v<<8n)|BigInt(bytes[i]); return '0x'+v.toString(16).toUpperCase(); })() : '-',
  };
}

export default function MemoryViewerPage() {
  const [address, setAddress] = useState('7FF600000000');
  const [pid, setPid] = useState('');
  const [memoryData, setMemoryData] = useState(null);
  const [prevData, setPrevData] = useState(null);
  const [selectedStart, setSelectedStart] = useState(-1);
  const [selectedEnd, setSelectedEnd] = useState(-1);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshRate, setRefreshRate] = useState(500);
  const [bookmarks, setBookmarks] = useState(() => {
    try { return JSON.parse(localStorage.getItem('bifrost_bookmarks') || '[]'); } catch { return []; }
  });
  const [loading, setLoading] = useState(false);
  const [readError, setReadError] = useState('');
  const [chain, setChain] = useState([]); // ptr chase history
  const [writeHex, setWriteHex] = useState('');
  const [writeError, setWriteError] = useState('');
  const [gotoOff, setGotoOff] = useState('');

  const api = window.bifrost;
  const intervalRef = useRef(null);
  const ROWS = 32;
  const BYTES_PER_ROW = 16;
  const READ_SIZE = ROWS * BYTES_PER_ROW;

  const readMemory = useCallback(async () => {
    if (!api || !pid) return;
    const addr = parseHexInput(address);
    if (isNaN(addr)) {
      setReadError('Invalid address — enter a hex value like 7FF600000000');
      return;
    }

    setLoading(true);
    setReadError('');
    try {
      const result = await api.command('read_memory', {
        pid: parseInt(pid),
        address: addr,
        size: READ_SIZE,
      });
      // Request-response results arrive as {type:'result', data:{bytes: [...]}}
      const payload = result?.type === 'result' ? result.data : result;
      if (payload && Array.isArray(payload.bytes)) {
        setPrevData(memoryData);
        setMemoryData(payload.bytes);
        setReadError('');
        if (window.bifrost?.toast) window.bifrost.toast(`Read ${payload.bytes.length} bytes`, 'success');
      } else if (payload?.error) {
        const msg = payload.code ? `${payload.code}: ${payload.error}` : payload.error;
        console.error('Memory read failed:', msg);
        setReadError(msg);
        setMemoryData(null);
        if (window.bifrost?.toast) window.bifrost.toast(msg, 'error');
      } else {
        setReadError('Unexpected response from backend');
        setMemoryData(null);
      }
    } catch (e) {
      const msg = e?.message || String(e);
      console.error('Memory read failed:', e);
      setReadError(msg);
      setMemoryData(null);
      if (window.bifrost?.toast) window.bifrost.toast(msg, 'error');
    }
    setLoading(false);
  }, [api, pid, address, memoryData]);

  useEffect(() => {
    if (autoRefresh && pid) {
      intervalRef.current = setInterval(readMemory, refreshRate);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, refreshRate, readMemory, pid]);

  useEffect(() => {
    localStorage.setItem('bifrost_bookmarks', JSON.stringify(bookmarks));
  }, [bookmarks]);

  const baseAddr = parseHexInput(address) || 0;
  const bytes = memoryData || new Array(READ_SIZE).fill(0);
  const prev = prevData || bytes;

  const rows = [];
  for (let r = 0; r < ROWS; r++) {
    const rowBytes = bytes.slice(r * BYTES_PER_ROW, (r + 1) * BYTES_PER_ROW);
    const prevBytes = prev.slice(r * BYTES_PER_ROW, (r + 1) * BYTES_PER_ROW);
    rows.push({ offset: r * BYTES_PER_ROW, bytes: rowBytes, prevBytes });
  }

  const selectedBytes = [];
  if (selectedStart >= 0 && selectedEnd >= selectedStart) {
    for (let i = selectedStart; i <= Math.min(selectedEnd, bytes.length - 1); i++) {
      selectedBytes.push(bytes[i]);
    }
  }
  const interp = interpretBytes(selectedBytes, selectedStart);

  const addBookmark = () => {
    if (selectedStart < 0) return;
    const addr = baseAddr + selectedStart;
    const label = prompt('Bookmark label:');
    if (label) {
      setBookmarks(prev => [...prev, { address: addr, label }]);
      if (window.bifrost?.toast) window.bifrost.toast('Bookmark added', 'success');
    }
  };

  const derefSelection = async () => {
    if (!api || !pid || selectedStart < 0) return;
    const selAddr = baseAddr + selectedStart;
    // read 8 bytes at selection as little-endian ptr
    try {
      const res = await api.command('read_memory', { pid: parseInt(pid), address: selAddr, size: 8 });
      const p = res?.type === 'result' ? res.data : res;
      if (p?.error) { setWriteError(p.error); return; }
      const b = p?.bytes; if (!Array.isArray(b) || b.length < 8) { setWriteError('Not enough bytes for pointer'); return; }
      let ptr = 0n; for (let i=7;i>=0;i--) ptr = (ptr << 8n) | BigInt(b[i]);
      const hex = ptr.toString(16).toUpperCase();
      setChain(prev => [...prev.slice(-8), { from: selAddr, to: Number(ptr) }]);
      setAddress(hex);
      if (window.bifrost?.toast) window.bifrost.toast(`Deref → 0x${hex}`, 'success');
      setTimeout(() => readMemory(), 120);
    } catch (e) { setWriteError(e?.message || String(e)); }
  };

  const writeMemory = async () => {
    if (!api || !pid || selectedStart < 0 || !writeHex.trim()) return;
    const bytes = writeHex.trim().split(/[\s,]+/).map(s => parseInt(s,16)).filter(n => !isNaN(n) && n>=0 && n<=255);
    if (!bytes.length) { setWriteError('Enter hex bytes like: 90 90 CC or FF 00 01'); return; }
    const addrStr = fmtAddr(baseAddr + selectedStart);
    const doWrite = async () => {
      try {
        const res = await api.command('write_memory', { pid: parseInt(pid), address: baseAddr + selectedStart, bytes });
        const p = res?.type === 'result' ? res.data : res;
        if (p?.error) { setWriteError(p.error); if (window.bifrost?.toast) window.bifrost.toast(p.error,'error'); }
        else { setWriteError(''); if (window.bifrost?.toast) window.bifrost.toast(`Wrote ${bytes.length} bytes @ ${addrStr}`,'success'); readMemory(); }
      } catch (e) { setWriteError(e?.message || String(e)); }
    };
    if (window.bifrost?.confirmDestructive) {
      window.bifrost.confirmDestructive({ title: `Write ${bytes.length} bytes to ${addrStr}?`, body: `Target PID ${pid} — ${bytes.map(b=>b.toString(16).toUpperCase().padStart(2,'0')).join(' ')} — direct attach only, no driver. This mutates live memory.`, confirmLabel: 'Write', onConfirm: doWrite });
    } else if (window.confirm(`Write ${bytes.length} bytes to ${addrStr}? ${bytes.map(b=>b.toString(16).toUpperCase().padStart(2,'0')).join(' ')}`)) {
      doWrite();
    }
  };

  const isInitialEmpty = !memoryData && !loading && !readError;

  return (
    <>
      <div className="page-header">
        <div className="page-title">Memory Viewer</div>
        <div className="page-subtitle">Live hex editor with type interpretation</div>
      </div>

      <div className="hex-toolbar" style={{ gap: 8, flexWrap: 'wrap' }}>
        <input className="input-field" style={{ width: 84, fontSize: 12, background: '#050507', borderColor: 'rgba(0,0,0,0.6)', boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6), inset -1px -1px 0 rgba(255,255,255,0.06)' }} placeholder="PID" value={pid} onChange={(e) => setPid(e.target.value)} />
        <span style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>@</span>
        <input className="hex-address-input" placeholder="0x7FF600000000" value={address} onChange={(e) => setAddress(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') readMemory(); }} style={{ width: 200, background: '#050507', borderColor: 'rgba(0,0,0,0.6)', boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6), inset -1px -1px 0 rgba(255,255,255,0.06)' }} />
        <button className="btn btn-primary" onClick={readMemory} disabled={loading || !pid} style={{ fontSize: 12 }}>{loading ? 'Reading...' : 'Read'}</button>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', background: '#050507', border: '1px solid rgba(0,0,0,0.6)', borderRadius: 3, padding: '3px 6px', boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6)' }}>
          <span style={{ fontSize: 10, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>+OFF</span>
          <input className="input-field" style={{ width: 86, padding: '4px 6px', fontSize: 11, background: 'transparent', border: 'none', boxShadow: 'none' }} placeholder="0x10" value={gotoOff} onChange={e=>setGotoOff(e.target.value)} onKeyDown={e=>{ if(e.key==='Enter'){ const off=parseHexInput(gotoOff); if(!isNaN(off)){ const base=parseHexInput(address)||0; const nxt=base+off; setAddress(nxt.toString(16).toUpperCase()); setTimeout(()=>readMemory(),80); }}}} />
          <button className="btn" style={{ padding: '3px 8px', fontSize: 10 }} onClick={()=>{ const off=parseHexInput(gotoOff); if(isNaN(off)) return; const base=parseHexInput(address)||0; const nxt=base+off; setAddress(nxt.toString(16).toUpperCase()); setTimeout(()=>readMemory(),80); }}>Go</button>
        </div>
        <button className="btn" style={{ fontSize: 10, padding: '6px 8px' }} onClick={()=>{ const s=selectedBytes.map(b=>toHex(b)).join(' '); if(s && navigator.clipboard) navigator.clipboard.writeText(s).then(()=>window.bifrost?.toast && window.bifrost.toast('Hex copied','success')); }} disabled={selectedBytes.length===0}>Copy Hex</button>
        <button className="btn" style={{ fontSize: 10, padding: '6px 8px' }} onClick={()=>{ const a=selectedStart>=0 ? fmtAddr(baseAddr+selectedStart) : fmtAddr(baseAddr); if(navigator.clipboard) navigator.clipboard.writeText(a).then(()=>window.bifrost?.toast && window.bifrost.toast('Addr copied','success')); }} disabled={selectedStart<0 && !memoryData}>Copy Addr</button>
        <div style={{ flex: 1 }} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
          <button className={`settings-toggle ${autoRefresh ? 'on' : ''}`} onClick={() => setAutoRefresh(!autoRefresh)} aria-label="Auto refresh" />
          Auto ({refreshRate}ms)
        </label>
      </div>

      {readError && (
        <div style={{
          padding: '12px 16px', margin: '0 0 12px', borderRadius: 5,
          background: 'rgba(217,74,74,0.12)', border: '1px solid rgba(217,74,74,0.32)',
          borderTop: '1px solid rgba(255,255,255,0.10)',
          color: '#d94a4a', fontSize: 12, fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06), inset 0 -1px 0 rgba(0,0,0,0.45)'
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 14 }}>!</span>
            <span>{readError}</span>
          </span>
          <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 11 }} onClick={readMemory}>Retry</button>
        </div>
      )}

      {isInitialEmpty ? (
        <div className="empty-state">
          <div className="empty-title">No memory read yet</div>
          <p className="empty-hint">Enter a PID and hex address, then hit Read to inspect live memory.</p>
          <div className="empty-action"><button className="btn btn-primary" onClick={readMemory} disabled={!pid}>Read</button></div>
        </div>
      ) : loading ? (
        <div className="hex-container">
          <div className="hex-grid-wrapper">
            {Array.from({ length: ROWS }).map((_, ri) => (
              <div key={ri} className="hex-row">
                <span className="hex-address" style={{ width: 120, flexShrink: 0 }}>
                  <span className="skeleton skeleton-cell" style={{ width: 96, height: 8, display: 'inline-block' }} />
                </span>
                <div className="hex-bytes" style={{ flex: 1, gap: 4 }}>
                  {Array.from({ length: BYTES_PER_ROW }).map((__, bi) => (
                    <span key={bi} className="skeleton" style={{ width: 22, height: 14, borderRadius: 2, display: 'inline-block' }} />
                  ))}
                </div>
                <span className="hex-ascii" style={{ width: 160, flexShrink: 0, marginLeft: 16 }}>
                  <span className="skeleton skeleton-cell" style={{ width: 88, height: 8, display: 'inline-block' }} />
                </span>
              </div>
            ))}
          </div>
          <div className="hex-interpreter">
            <div className="hex-interp-title" style={{ fontWeight: 600, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>Type Interpreter</div>
            <div className="skeleton-row" style={{ padding: '6px 0' }}><div className="skeleton skeleton-cell" style={{ width: '100%', height: 10 }} /></div>
            <div className="skeleton-row" style={{ padding: '6px 0' }}><div className="skeleton skeleton-cell" style={{ width: '80%', height: 10 }} /></div>
          </div>
        </div>
      ) : (
        <div className="hex-container">
          <div className="hex-grid-wrapper" role="grid" aria-label="Memory hex view">
            <div className="hex-row" style={{ background: '#0a0a0c', borderBottom: '1px solid rgba(255,255,255,0.08)', position: 'sticky', top: 0, zIndex: 1, fontSize: 10, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', letterSpacing: '0.04em' }}>
              <span style={{ width: 56, flexShrink: 0, textAlign: 'right', paddingRight: 8 }}>+OFF</span>
              <span className="hex-address" style={{ width: 120 }}>ADDRESS</span>
              <span style={{ flex: 1, textAlign: 'center' }}>00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
              <span style={{ width: 160, flexShrink: 0, marginLeft: 16 }}>ASCII</span>
            </div>
            {rows.map((row, ri) => (
              <div key={ri} className="hex-row" role="row">
                <span style={{ width: 56, flexShrink: 0, textAlign: 'right', paddingRight: 8, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11, userSelect: 'none' }}>+{row.offset.toString(16).toUpperCase().padStart(3,'0')}</span>
                <span className="hex-address" role="rowheader">
                  {(baseAddr + row.offset).toString(16).toUpperCase().padStart(12, '0')}
                </span>
                <div className="hex-bytes" role="row">
                  {row.bytes.map((b, bi) => {
                    const idx = ri * BYTES_PER_ROW + bi;
                    const changed = prev && prev[idx] !== undefined && prev[idx] !== b && memoryData;
                    const selected = idx >= selectedStart && idx <= selectedEnd;
                    const isZero = b === 0;
                    return (
                       <span
                        key={bi}
                        role="gridcell"
                        tabIndex={0}
                        aria-selected={selected}
                        aria-label={`Byte ${idx} @ ${fmtAddr(baseAddr+idx)} value ${toHex(b)}`}
                        className={`hex-byte${selected ? ' selected' : ''}${changed ? ' changed' : ''}${isZero ? ' zero' : ''}`}
                        onClick={() => { setSelectedStart(idx); setSelectedEnd(Math.min(idx + 7, bytes.length - 1)); }}
                        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedStart(idx); setSelectedEnd(Math.min(idx + 7, bytes.length - 1)); } if (e.key === 'c' && (e.ctrlKey||e.metaKey)) { e.preventDefault(); const v=toHex(b); if(navigator.clipboard) navigator.clipboard.writeText(v); } }}
                        title={`${fmtAddr(baseAddr+idx)}  ${toHex(b)}  '${toAscii(b)}'  — click to select 8, Ctrl+C to copy`}
                      >
                        {toHex(b)}
                      </span>
                    );
                  })}
                </div>
                <span className="hex-ascii">
                  {row.bytes.map((b, bi) => (
                    <span key={bi} className={b >= 32 && b <= 126 ? 'printable' : 'non-printable'}>
                      {toAscii(b)}
                    </span>
                  ))}
                </span>
              </div>
            ))}
          </div>

          <div className="hex-interpreter">
            <div className="hex-interp-title" style={{ fontWeight: 600, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>Type Interpreter</div>
            {selectedBytes.length === 0 ? (
              <div style={{ color: 'var(--text-ghost)', fontSize: 11, fontFamily: 'var(--font-mono)', border: '1px dashed var(--border)', borderRadius: 3, padding: 10, textAlign: 'center' }}>Click a byte to inspect</div>
            ) : (
              <>
                <div className="hex-interp-row"><span className="hex-interp-label">Offset</span><span className="hex-interp-value">0x{(baseAddr + selectedStart).toString(16).toUpperCase()}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">int8</span><span className="hex-interp-value">{interp.int8}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">uint8</span><span className="hex-interp-value">{interp.uint8}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">int16</span><span className="hex-interp-value">{interp.int16}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">uint16</span><span className="hex-interp-value">{interp.uint16}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">int32</span><span className="hex-interp-value">{interp.int32}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">uint32</span><span className="hex-interp-value">{interp.uint32}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">float</span><span className="hex-interp-value">{interp.float}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">double</span><span className="hex-interp-value">{interp.double}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">hex</span><span className="hex-interp-value" style={{ fontSize: 10 }}>{interp.hex}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">ascii</span><span className="hex-interp-value">{interp.ascii}</span></div>
                <div className="hex-interp-row"><span className="hex-interp-label">ptr64</span><span className="hex-interp-value" style={{ color: '#7EFF3F', textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>{interp.ptr64}</span></div>
                <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                  <button className="btn btn-secondary" style={{ flex: 1, fontSize: 10, padding: '6px 4px' }} onClick={derefSelection} disabled={selectedStart < 0 || !pid}>Deref ptr →</button>
                  <button className="btn" style={{ flex: 1, fontSize: 10, padding: '6px 4px' }} onClick={() => { if(chain.length) { const last = chain[chain.length-1]; setAddress(last.to.toString(16).toUpperCase()); } }} disabled={!chain.length}>Jump back</button>
                </div>
                {chain.length > 0 && (
                  <div style={{ marginTop: 8, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)', lineHeight: 1.4, borderTop: '1px solid var(--border)', paddingTop: 6 }}>
                    Chain: {chain.map((c,i) => <span key={i}>{fmtAddr(c.from)}→{fmtAddr(c.to)}{i<chain.length-1?' · ':''}</span>)}
                  </div>
                )}
                <div style={{ marginTop: 10, display: 'flex', gap: 6, alignItems: 'center' }}>
                  <input className="input-field" placeholder="90 90 CC" value={writeHex} onChange={e=>setWriteHex(e.target.value)} style={{ flex: 1, fontSize: 11, padding: '6px 8px' }} />
                  <button className="btn btn-primary" style={{ fontSize: 10, padding: '6px 10px' }} onClick={writeMemory} disabled={!pid || selectedStart<0}>Write</button>
                </div>
                {writeError && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--error)', marginTop: 4 }}>{writeError}</div>}
              </>
            )}

            <div className="hex-bookmarks">
              <div className="hex-interp-title" style={{ marginTop: 16, fontWeight: 600, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>
                Bookmarks
                {selectedStart >= 0 && (
                  <button className="btn" style={{ marginLeft: 8, padding: '2px 8px', fontSize: 10 }} onClick={addBookmark}>+</button>
                )}
              </div>
              {bookmarks.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>No bookmarks yet</div>
              ) : (
                bookmarks.map((bm, i) => (
                  <div
                    key={i}
                    className="hex-bookmark-item"
                    onClick={() => setAddress(bm.address.toString(16).toUpperCase())}
                  >
                    <span>{bm.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--bg-input)' }}>
                      0x{bm.address.toString(16).toUpperCase()}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
