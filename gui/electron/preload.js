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

  startGeneration: (opts) => ipcRenderer.send('start-generation', opts),
  onGenLog: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('gen-log', handler);
    return () => ipcRenderer.removeListener('gen-log', handler);
  },
  onGenError: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('gen-error', handler);
    return () => ipcRenderer.removeListener('gen-error', handler);
  },
  onGenProgress: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('gen-progress', handler);
    return () => ipcRenderer.removeListener('gen-progress', handler);
  },
  onGenComplete: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('gen-complete', handler);
    return () => ipcRenderer.removeListener('gen-complete', handler);
  },

  startHunt: (opts) => ipcRenderer.send('start-hunt', opts),
  onHuntLog: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('hunt-log', handler);
    return () => ipcRenderer.removeListener('hunt-log', handler);
  },
  onHuntError: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('hunt-error', handler);
    return () => ipcRenderer.removeListener('hunt-error', handler);
  },
  onHuntProgress: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('hunt-progress', handler);
    return () => ipcRenderer.removeListener('hunt-progress', handler);
  },
  onHuntComplete: (cb) => {
    const handler = (_, data) => cb(data);
    ipcRenderer.on('hunt-complete', handler);
    return () => ipcRenderer.removeListener('hunt-complete', handler);
  },

  saveFile: (opts) => ipcRenderer.invoke('save-file-dialog', opts),
  loadJsonFile: () => ipcRenderer.invoke('load-json-file'),
  selectDirectory: () => ipcRenderer.invoke('select-directory'),

  removeAllListeners: (channel) => {
    // Restrict to known streaming channels only — prevents renderer from
    // removing listeners on arbitrary Electron IPC channels
    const ALLOWED_CHANNELS = [
      'dump-progress', 'dump-log', 'dump-error', 'dump-complete',
      'spoof-progress', 'spoof-log', 'spoof-error', 'spoof-complete',
      'gen-progress', 'gen-log', 'gen-error', 'gen-complete',
      'hunt-progress', 'hunt-log', 'hunt-error', 'hunt-complete',
    ];
    if (ALLOWED_CHANNELS.includes(channel)) {
      ipcRenderer.removeAllListeners(channel);
    }
  },
});
