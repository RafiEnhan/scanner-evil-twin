const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');

let mainWindow;
let pythonProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 720,
    title: "PuriFier — Pre-Connection Wireless Threat Intelligence",
    backgroundColor: '#090c10',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  mainWindow.loadFile('index.html');

  const fs = require('fs');
  const logFilePath = path.join(app.getPath('userData'), 'purifier-app.log');

  function logToFile(msg) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] ${msg}\n`;
    try {
      fs.appendFileSync(logFilePath, logLine);
    } catch (err) {
      console.error("Failed to write to log file:", err);
    }
  }

  logToFile(`--- App Started (Platform: ${process.platform}, Arch: ${process.arch}) ---`);
  logToFile(`Log file location: ${logFilePath}`);

  process.on('uncaughtException', (error) => {
    logToFile(`[CRITICAL UNCAUGHT EXCEPTION]: ${error ? (error.stack || error.message || error) : 'Unknown error'}`);
  });

  process.on('unhandledRejection', (reason) => {
    logToFile(`[CRITICAL UNHANDLED REJECTION]: ${reason ? (reason.stack || reason) : 'Unknown rejection'}`);
  });

  function findPython3() {
    if (process.platform === 'win32') return 'python';
    const candidates = [
      '/Library/Frameworks/Python.framework/Versions/3.11/bin/python3',
      '/usr/local/bin/python3',
      '/opt/homebrew/bin/python3',
      '/usr/bin/python3',
      'python3'
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    return 'python3';
  }

  const exeName = process.platform === 'win32' ? 'purifier_backend.exe' : 'purifier_backend';
  const backendCandidates = [
    path.join(process.resourcesPath, 'dist', 'purifier_backend', exeName),
    path.join(process.resourcesPath, 'purifier_backend', exeName),
    path.join(__dirname, 'dist', 'purifier_backend', exeName),
    path.join(__dirname, 'dist', 'purifier_backend'),
    path.join(process.resourcesPath, exeName)
  ];

  let binaryToRun = null;
  for (const cand of backendCandidates) {
    if (fs.existsSync(cand)) {
      binaryToRun = cand;
      break;
    }
  }

  if (binaryToRun) {
    logToFile(`Spawning PyInstaller backend binary: ${binaryToRun}`);
    pythonProcess = spawn(binaryToRun, [], { cwd: path.dirname(binaryToRun) });
  } else {
    const pythonExecutable = findPython3();
    const backendScript = path.join(__dirname, 'purifier_backend.py');
    logToFile(`Fallback: Spawning Python script (${pythonExecutable} ${backendScript})`);
    const customEnv = Object.assign({}, process.env, {
      PATH: `/Library/Frameworks/Python.framework/Versions/3.11/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:${process.env.PATH || ''}`
    });
    pythonProcess = spawn(pythonExecutable, [backendScript], { env: customEnv });
  }

  pythonProcess.stdout.on('data', (data) => {
    const text = data.toString();
    const lines = text.split('\n');
    lines.forEach(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith('{')) {
        try {
          const jsonEvent = JSON.parse(trimmed);
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-event', jsonEvent);
          }
        } catch (e) {
          logToFile(`JSON parse error: ${e.message}`);
        }
      } else if (trimmed) {
        logToFile(`[Python STDOUT]: ${trimmed}`);
      }
    });
  });

  pythonProcess.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) {
      logToFile(`[Python STDERR]: ${msg}`);
      console.error(`[Python Terminal Message]: ${msg}`);
    }
  });

  pythonProcess.on('error', (err) => {
    logToFile(`[Python Process ERROR]: ${err.message}`);
  });

  pythonProcess.on('exit', (code, signal) => {
    logToFile(`[Python Process EXITED]: Code ${code}, Signal ${signal}`);
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

function killPythonAndQuit() {
  if (pythonProcess) {
    try { pythonProcess.kill('SIGKILL'); } catch (e) {}
  }
  try {
    exec("pkill -f purifier_backend.py", () => {});
  } catch (e) {}
}

app.on('window-all-closed', () => {
  killPythonAndQuit();
  app.quit();
});

app.on('before-quit', () => {
  killPythonAndQuit();
});

app.on('will-quit', () => {
  killPythonAndQuit();
});

ipcMain.handle('execute-os-ban', async (event, banPayload) => {
  return new Promise((resolve) => {
    const { execFile } = require('child_process');
    let commandStr = '';
    let ssid = '';
    let bssid = '';

    if (typeof banPayload === 'string') {
      commandStr = banPayload;
    } else if (banPayload && typeof banPayload === 'object') {
      commandStr = banPayload.commandStr || '';
      ssid = banPayload.ssid || '';
      bssid = banPayload.bssid || '';
    }

    if (!commandStr || commandStr.startsWith("N/A")) {
      return resolve({ success: false, output: "Command not applicable." });
    }

    // Safe execution based on host OS platform without shell wrapper
    if (process.platform === 'darwin') {
      if (!ssid && commandStr.includes("networksetup")) {
        const match = commandStr.match(/networksetup\s+-removepreferredwirelessnetwork\s+\S+\s+'?(.*?)'?$/);
        if (match) ssid = match[1];
      }
      if (!ssid) {
        return resolve({ success: false, output: "Invalid SSID for networksetup enforcement." });
      }
      execFile('networksetup', ['-removepreferredwirelessnetwork', 'en0', ssid], (error, stdout, stderr) => {
        const fullOutput = (stdout || '').trim() || (stderr || '').trim();
        if (error) {
          const detail = fullOutput || error.message || 'Unknown networksetup error';
          resolve({ success: false, output: detail });
        } else {
          resolve({ success: true, output: fullOutput || `Enforcement Executed: Blocked SSID '${ssid}' on macOS` });
        }
      });
    } else if (process.platform === 'win32') {
      if (!ssid && commandStr.includes("netsh")) {
        const match = commandStr.match(/ssid="?(.*?)"?\s+/);
        if (match) ssid = match[1];
      }
      if (!ssid) {
        return resolve({ success: false, output: "Invalid SSID for netsh enforcement." });
      }
      execFile('netsh', ['wlan', 'add', 'filter', 'permission=block', `ssid=${ssid}`, 'networktype=infrastructure'], (error, stdout, stderr) => {
        const fullOutput = (stdout || '').trim() || (stderr || '').trim();
        if (error) {
          let detail = fullOutput || error.message || 'Unknown netsh error';
          if (detail.toLowerCase().includes("requires elevation") || detail.toLowerCase().includes("access is denied")) {
            detail += "\n\n💡 Tip: Run PuriFier as Administrator to allow Windows filter modifications.";
          }
          resolve({ success: false, output: detail });
        } else {
          resolve({ success: true, output: fullOutput || `Enforcement Executed: Blocked SSID '${ssid}' on Windows` });
        }
      });
    } else {
      // Linux or fallback
      if (!bssid && commandStr.includes("nmcli")) {
        const match = commandStr.match(/bssid\s+([0-9a-fa-f:]+)/i);
        if (match) bssid = match[1];
      }
      if (bssid) {
        execFile('nmcli', ['device', 'wifi', 'block', 'bssid', bssid], (error, stdout, stderr) => {
          const fullOutput = (stdout || '').trim() || (stderr || '').trim();
          if (error) {
            if (ssid) {
              execFile('nmcli', ['connection', 'delete', ssid], (err2, out2, errOut2) => {
                const subOutput = (out2 || '').trim() || (errOut2 || '').trim();
                if (err2) {
                  resolve({ success: false, output: subOutput || err2.message || 'Failed to delete connection on Linux' });
                } else {
                  resolve({ success: true, output: subOutput || `Enforcement Executed: Deleted connection '${ssid}' on Linux` });
                }
              });
            } else {
              resolve({ success: false, output: fullOutput || error.message || 'Failed to block BSSID on Linux' });
            }
          } else {
            resolve({ success: true, output: fullOutput || `Enforcement Executed: Blocked BSSID '${bssid}' on Linux` });
          }
        });
      } else if (ssid) {
        execFile('nmcli', ['device', 'wifi', 'block', 'bssid', bssid], (error, stdout, stderr) => {
          const fullOutput = (stdout || '').trim() || (stderr || '').trim();
          if (error) {
            resolve({ success: false, output: fullOutput || error.message || 'Failed to block SSID on Linux' });
          } else {
            resolve({ success: true, output: fullOutput || `Enforcement Executed: Blocked BSSID '${bssid}' on Linux` });
          }
        });
      } else {
        resolve({ success: false, output: "Unsupported platform or missing BSSID." });
      }
    }
  });
});

ipcMain.handle('open-log-file', async () => {
  const { shell } = require('electron');
  const logFilePath = path.join(app.getPath('userData'), 'purifier-app.log');
  if (fs.existsSync(logFilePath)) {
    shell.showItemInFolder(logFilePath);
    return { success: true, path: logFilePath };
  }
  return { success: false, message: "Log file does not exist yet." };
});
