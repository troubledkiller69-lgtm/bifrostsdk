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

  const api = window.bifrost;
  const intervalRef = useRef(null);
  const ROWS = 32;
  const BYTES_PER_ROW = 16;
  const READ_SIZE = ROWS * BYTES_PER_ROW;

  const readMemory = useCallback(async () => {
    if (!api || !pid) return;
    const addr = parseHexInput(address);
    if (isNaN(addr)) return;

    setLoading(true);
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
      } else if (payload?.error) {
        console.error('Memory read failed:', payload.error);
        setMemoryData(null);
      }
    } catch (e) {
      console.error('Memory read failed:', e);
      setMemoryData(null);
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
    }
  };

  return (
    <>
      <div className="page-header">
        <div className="page-title">Memory Viewer</div>
        <div className="page-subtitle">Live hex editor with type interpretation</div>
      </div>

      <div className="hex-toolbar">
        <input
          className="input-field"
          style={{ width: 100 }}
          placeholder="PID"
          value={pid}
          onChange={(e) => setPid(e.target.value)}
        />
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>@</span>
        <input
          className="hex-address-input"
          placeholder="0x7FF600000000"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') readMemory(); }}
        />
        <button className="btn btn-primary" onClick={readMemory} disabled={loading || !pid}>
          {loading ? 'Reading...' : 'Read'}
        </button>
        <div style={{ flex: 1 }} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer' }}>
          <button
            className={`settings-toggle ${autoRefresh ? 'on' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
          />
          Auto ({refreshRate}ms)
        </label>
      </div>

      <div className="hex-container">
        <div className="hex-grid-wrapper">
          {rows.map((row, ri) => (
            <div key={ri} className="hex-row">
              <span className="hex-address">
                {(baseAddr + row.offset).toString(16).toUpperCase().padStart(12, '0')}
              </span>
              <div className="hex-bytes">
                {row.bytes.map((b, bi) => {
                  const idx = ri * BYTES_PER_ROW + bi;
                  const changed = prev && prev[idx] !== undefined && prev[idx] !== b && memoryData;
                  const selected = idx >= selectedStart && idx <= selectedEnd;
                  const isZero = b === 0;
                  return (
                    <span
                      key={bi}
                      className={`hex-byte${selected ? ' selected' : ''}${changed ? ' changed' : ''}${isZero ? ' zero' : ''}`}
                      onClick={() => { setSelectedStart(idx); setSelectedEnd(Math.min(idx + 7, bytes.length - 1)); }}
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
          <div className="hex-interp-title">Type Interpreter</div>
          {selectedBytes.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Click a byte to inspect</div>
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
              <div className="hex-interp-row"><span className="hex-interp-label">hex</span><span className="hex-interp-value">{interp.hex}</span></div>
              <div className="hex-interp-row"><span className="hex-interp-label">ascii</span><span className="hex-interp-value">{interp.ascii}</span></div>
            </>
          )}

          <div className="hex-bookmarks">
            <div className="hex-interp-title" style={{ marginTop: 16 }}>
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
    </>
  );
}
