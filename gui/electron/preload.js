/**
 * BIFROST SDK — Renderer Bridge Surface (preload)
 *
 * This is the public API exposed to the React frontend.
 *
 * IMPORTANT: The authoritative contract for the underlying IPC (commands, streaming
 * commands, events, error shapes, and protocol_version envelopes) lives in:
 *   contracts/bifrost_protocol.json
 *
 * Changes to the command/event surface must be made in the protocol first.
 * This file is intentionally kept as a thin, stable contextBridge layer.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('bifrost', {
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),

  command: (command, args) => ipcRenderer.invoke('python-command', { command, args }),

  startDump: (opts) => ipcRenderer.send('start-dump', opts),
  stopDump: () => ipcRenderer.send('stop-dump'),

  // Improved listener registration (v1.1+ hygiene)
  // These now return an unsubscribe() function for clean, per-callback removal.
  // Existing code that ignores the return value continues to work.
  onDumpProgress: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('dump-progress', handler);
    return () => ipcRenderer.removeListener('dump-progress', handler);
  },
  onDumpAccess: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('dump-access', handler);
    return () => ipcRenderer.removeListener('dump-access', handler);
  },
  onDumpLog: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('dump-log', handler);
    return () => ipcRenderer.removeListener('dump-log', handler);
  },
  onDumpError: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('dump-error', handler);
    return () => ipcRenderer.removeListener('dump-error', handler);
  },
  onDumpComplete: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('dump-complete', handler);
    return () => ipcRenderer.removeListener('dump-complete', handler);
  },

  startSpoofing: (opts) => ipcRenderer.send('start-spoofing', opts),
  onSpoofLog: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('spoof-log', handler);
    return () => ipcRenderer.removeListener('spoof-log', handler);
  },
  onSpoofError: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('spoof-error', handler);
    return () => ipcRenderer.removeListener('spoof-error', handler);
  },
  onSpoofProgress: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('spoof-progress', handler);
    return () => ipcRenderer.removeListener('spoof-progress', handler);
  },
  onSpoofComplete: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('spoof-complete', handler);
    return () => ipcRenderer.removeListener('spoof-complete', handler);
  },

  startAnalyze: (opts) => ipcRenderer.send('start-analyze', opts),
  stopAnalyze: () => ipcRenderer.send('stop-analyze'),
  startAnalyzeExport: (opts) => ipcRenderer.send('start-analyze-export', opts),
  stopAnalyzeExport: () => ipcRenderer.send('stop-analyze-export'),
  analyzeProbe: () => ipcRenderer.invoke('python-command', { command: 'analyze_probe', args: {} }),
  decompileFn: (addr) => ipcRenderer.invoke('python-command', { command: 'decompile_fn', args: { addr } }),
  analyzerHexdump: (addr, size) => ipcRenderer.invoke('python-command', { command: 'analyzer_hexdump', args: { addr, size } }),
  analyzerDisasmAt: (addr, size) => ipcRenderer.invoke('python-command', { command: 'analyzer_disasm_at', args: { addr, size } }),
  analyzerXrefs: (addr) => ipcRenderer.invoke('python-command', { command: 'analyzer_xrefs', args: { addr } }),
  analyzerSymbols: () => ipcRenderer.invoke('python-command', { command: 'analyzer_symbols', args: {} }),
  analyzerStrings: (minLen, cap) => ipcRenderer.invoke('python-command', { command: 'analyzer_strings', args: { min_len: minLen, cap } }),
  debugSnapshot: (includeThreads) => ipcRenderer.invoke('python-command', { command: 'debug_snapshot', args: { include_threads: !!includeThreads } }),
  onAnalyzeLog: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('analyze-log', handler);
    return () => ipcRenderer.removeListener('analyze-log', handler);
  },
  onAnalyzeError: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('analyze-error', handler);
    return () => ipcRenderer.removeListener('analyze-error', handler);
  },
  onAnalyzeProgress: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('analyze-progress', handler);
    return () => ipcRenderer.removeListener('analyze-progress', handler);
  },
  onAnalyzeComplete: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('analyze-complete', handler);
    return () => ipcRenderer.removeListener('analyze-complete', handler);
  },

  saveFile: (opts) => ipcRenderer.invoke('save-file-dialog', opts),
  loadJsonFile: () => ipcRenderer.invoke('load-json-file'),
  selectFilePath: () => ipcRenderer.invoke('select-file-path'),

  removeAllListeners: (channel) => {
    // Restrict to known streaming channels only — prevents renderer from
    // removing listeners on arbitrary Electron IPC channels
    const ALLOWED_CHANNELS = [
      'dump-progress', 'dump-log', 'dump-error', 'dump-complete', 'dump-access',
      'spoof-progress', 'spoof-log', 'spoof-error', 'spoof-complete',
      'analyze-progress', 'analyze-log', 'analyze-error', 'analyze-complete',
    ];
    if (ALLOWED_CHANNELS.includes(channel)) {
      ipcRenderer.removeAllListeners(channel);
    }
  },
});
