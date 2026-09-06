const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const readline = require('readline');
const fs = require('fs');

let mainWindow;
let apiServerProc = null;

// Track pending promises for normal commands
let pendingRequests = {};
let reqIdCounter = 1;

// BIFROST IPC Protocol version (must stay in sync with contracts/bifrost_protocol.json)
const BIFROST_PROTOCOL_VERSION = '1.2';

// Per-operation streaming channels. Events emitted by the backend carry a
// `stream` tag (the command name), so each operation only reaches its own
// channels — no cross-contamination between dump/spoof/gen/hunt.
const STREAMING_CHANNELS = {
  dump:   { log: 'dump-log',   error: 'dump-error',   progress: 'dump-progress',   complete: 'dump-complete' },
  spoof:  { log: 'spoof-log',  error: 'spoof-error',  progress: 'spoof-progress',  complete: 'spoof-complete' },
  generate: { log: 'gen-log',  error: 'gen-error',    progress: 'gen-progress',    complete: 'gen-complete' },
  hunt:   { log: 'hunt-log',   error: 'hunt-error',   progress: 'hunt-progress',   complete: 'hunt-complete' },
};
const ALL_STREAMING_CHANNELS = Object.values(STREAMING_CHANNELS).flatMap(s => Object.values(s));

// Command allow-list for IPC (prevents renderer from sending arbitrary commands)
const ALLOWED_COMMANDS = [
  'ping', 'bridge_info',
  'list_processes',
  'test_webhook', 'spoof_info', 'spoof_restore', 'read_memory', 'ac_detect',
];

// Max content size for save-file-dialog (50MB)
const MAX_SAVE_SIZE = 50 * 1024 * 1024;

/**
 * Create a structured error object matching the protocol error_shape.
 * Uses "error" (not "message") for consistency with existing bridge payloads.
 * Used for local failures before/after talking to Python.
 */
function makeBridgeError(code, message, details = null) {
  const err = { error: message, code };
  if (details) err.details = details;
  return err;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 1000,
    minHeight: 700,
    frame: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      backgroundThrottling: false,
    },
    icon: app.isPackaged
      ? path.join(path.dirname(app.getPath('exe')), 'icon.ico')
      : path.join(__dirname, '..', 'public', 'favicon.ico'),
    backgroundColor: '#0a0a0f'
  });

  if (app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
  } else {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  }
}

ipcMain.on('window-minimize', () => mainWindow?.minimize());
ipcMain.on('window-maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow?.unmaximize();
  else mainWindow?.maximize();
});
ipcMain.on('window-close', () => mainWindow?.close());

function startApiServer() {
  const isPackaged = app.isPackaged;
  
  if (isPackaged) {
    const exePath = path.join(path.dirname(app.getPath('exe')), 'api_server.exe');
    apiServerProc = spawn(exePath, [], { cwd: path.dirname(exePath), stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  } else {
    const sdkRoot = path.join(__dirname, '..', '..');
    const pyScript = path.join(sdkRoot, 'api_server.py');
    apiServerProc = spawn('python', [pyScript], { cwd: sdkRoot, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  }

  // Read line by line from stdout
  const rl = readline.createInterface({
    input: apiServerProc.stdout,
    terminal: false
  });

  rl.on('line', (line) => {
    try {
      const msg = JSON.parse(line);
      
      // Handle normal request responses (id-based correlation)
      if (msg._id && pendingRequests[msg._id]) {
        // Normalize structured errors coming from Python (protocol error_shape)
        if (msg.data && msg.data.error) {
          const normalized = {
            ...msg,
            error: msg.data.error,
            code: msg.data.code || 'BRIDGE_ERROR',
            details: msg.data.details || null
          };
          pendingRequests[msg._id].resolve(normalized);
        } else {
          pendingRequests[msg._id].resolve(msg);
        }
        delete pendingRequests[msg._id];
        return;
      }

      // Handle streaming events, routed by the operation's stream tag.
      const op = STREAMING_CHANNELS[msg.stream];
      if (msg.type === 'log') {
        if (op) {
          mainWindow.webContents.send(op.log, msg);
          if (msg.level === 'error') {
            mainWindow.webContents.send(op.error, { type: 'error', text: msg.text, level: 'error' });
          }
        }
      } else if (msg.type === 'progress') {
        if (op) {
          mainWindow.webContents.send(op.progress, msg);
        }
      } else if (msg.type === 'result') {
        if (op) {
          // Backend errors arrive as {type:'result', data:{error:...}}
          if (msg.data && msg.data.error) {
            const errorMsg = { type: 'error', text: msg.data.error, level: 'error', details: msg.data.details || null };
            mainWindow.webContents.send(op.error, errorMsg);
            mainWindow.webContents.send(op.complete, errorMsg);
          } else {
            mainWindow.webContents.send(op.complete, msg);
          }
        }
      } else if (msg.type === 'error') {
        if (op) {
          mainWindow.webContents.send(op.error, msg);
        }
      }
    } catch (e) {
      console.log('API (raw):', line);
    }
  });

  apiServerProc.stderr.on('data', (d) => console.error('API Error:', d.toString()));

  // Crash recovery: if the Python backend exits unexpectedly, notify the UI
  apiServerProc.on('exit', (code, signal) => {
    console.error(`API server exited: code=${code}, signal=${signal}`);
    // Reject all pending requests
    for (const [id, pending] of Object.entries(pendingRequests)) {
      pending.resolve(makeBridgeError('BACKEND_CRASHED', `Python backend exited (code ${code})`));
      delete pendingRequests[id];
    }
    // Broadcast STREAM_INTERRUPTED to all streaming channels
    if (mainWindow && !mainWindow.isDestroyed()) {
      const interruptMsg = { type: 'error', text: `Backend process exited unexpectedly (code ${code})`, level: 'error' };
      for (const ch of ALL_STREAMING_CHANNELS) {
        mainWindow.webContents.send(ch, interruptMsg);
      }
    }
    apiServerProc = null;
  });
}

async function sendCommand(command, args = {}) {
  return new Promise((resolve, reject) => {
    if (!apiServerProc || apiServerProc.killed) {
      return resolve(makeBridgeError('BRIDGE_OFFLINE', 'Bridge Offline'));
    }
    
    const reqId = reqIdCounter++;
    pendingRequests[reqId] = { resolve, reject };
    
    // v1.1+ protocol envelope (matches contracts/bifrost_protocol.json)
    const payload = JSON.stringify({
      protocol_version: BIFROST_PROTOCOL_VERSION,
      command,
      args,
      id: reqId
    }) + '\n';
    
    try {
      apiServerProc.stdin.write(payload);
    } catch (e) {
      resolve(makeBridgeError('WRITE_FAILED', e.message));
      delete pendingRequests[reqId];
    }
    
    // Timeout
    setTimeout(() => {
      if (pendingRequests[reqId]) {
        resolve(makeBridgeError('TIMEOUT', 'Timeout waiting for bridge response'));
        delete pendingRequests[reqId];
      }
    }, 15000);
  });
}

function sendStreamingCommand(command, args = {}) {
  if (!apiServerProc || apiServerProc.killed) return;

  // v1.1+ protocol envelope. The backend echoes `stream` on every event it
  // emits for this operation, which is how main routes events per-channel.
  const payload = JSON.stringify({
    protocol_version: BIFROST_PROTOCOL_VERSION,
    command,
    args,
    stream: command,
  }) + '\n';

  try {
    apiServerProc.stdin.write(payload);
  } catch (e) {
    console.error('Failed to send streaming command', e);
  }
}

function cancelStreaming(command) {
  if (!apiServerProc || apiServerProc.killed) return;
  const payload = JSON.stringify({
    protocol_version: BIFROST_PROTOCOL_VERSION,
    command: 'cancel',
    args: { operation: command },
  }) + '\n';
  try {
    apiServerProc.stdin.write(payload);
  } catch (e) {
    console.error('Failed to send cancel', e);
  }
}

ipcMain.handle('python-command', async (event, { command, args }) => {
  // Allow-list check — streaming commands go through their own IPC channels
  if (!ALLOWED_COMMANDS.includes(command)) {
    return makeBridgeError('UNKNOWN_COMMAND', `Command not in allow-list: ${command}`);
  }
  try {
    return await sendCommand(command, args);
  } catch (err) {
    // Ensure we always return a structured bridge error
    return makeBridgeError('IPC_HANDLER_ERROR', err?.message || String(err));
  }
});

ipcMain.on('start-dump', (event, opts) => {
  sendStreamingCommand('dump', opts);
});

ipcMain.on('stop-dump', () => {
  cancelStreaming('dump');
});

ipcMain.on('start-spoofing', (event, opts) => {
  sendStreamingCommand('spoof', opts);
});

ipcMain.on('start-generation', (event, opts) => {
  sendStreamingCommand('generate', opts);
});

ipcMain.on('start-hunt', (event, opts) => {
  sendStreamingCommand('hunt', opts);
});

// Save file dialog (for export) — with content size limit
ipcMain.handle('save-file-dialog', async (event, { content, defaultName, filters }) => {
  if (typeof content === 'string' && content.length > MAX_SAVE_SIZE) {
    return { saved: false, error: `Content exceeds ${MAX_SAVE_SIZE / 1024 / 1024}MB limit` };
  }
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: defaultName,
    filters: filters || [{ name: 'All Files', extensions: ['*'] }],
  });
  if (!result.canceled && result.filePath) {
    fs.writeFileSync(result.filePath, content, 'utf-8');
    return { saved: true, path: result.filePath };
  }
  return { saved: false };
});

// Open file dialog (for loading JSON dumps in Diff Viewer)
ipcMain.handle('load-json-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    filters: [{ name: 'JSON Files', extensions: ['json'] }],
    properties: ['openFile'],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    const filePath = result.filePaths[0];
    const raw = fs.readFileSync(filePath, 'utf-8');
    try {
      return { data: JSON.parse(raw), filename: path.basename(filePath) };
    } catch {
      return { error: 'Invalid JSON' };
    }
  }
  return { cancelled: true };
});

// Select directory dialog (for output path in Settings/Boilerplate)
ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    return { path: result.filePaths[0] };
  }
  return { cancelled: true };
});

app.whenReady().then(() => {
  startApiServer();
  createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('quit', () => {
  if (apiServerProc) {
    apiServerProc.kill();
  }
});
