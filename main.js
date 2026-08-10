const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');

let mainWindow;
let pythonProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
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
    console.log("[*] 🚀 Spawning PyInstaller backend binary:", binaryToRun);
    pythonProcess = spawn(binaryToRun, []);
  } else {
    const pythonExecutable = findPython3();
    const backendScript = path.join(__dirname, 'purifier_backend.py');
    const customEnv = Object.assign({}, process.env, {
      PATH: `/Library/Frameworks/Python.framework/Versions/3.11/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:${process.env.PATH || ''}`
    });
    pythonProcess = spawn(pythonExecutable, [backendScript], { env: customEnv });
  }

  pythonProcess.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach(line => {
      if (line.trim().startsWith('{')) {
        try {
          const jsonEvent = JSON.parse(line.trim());
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-event', jsonEvent);
          }
        } catch (e) {
          console.error("JSON parse error:", e);
        }
      }
    });
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python Terminal Message]: ${data}`);
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
        if (error) {
          resolve({ success: false, output: stderr || error.message });
        } else {
          resolve({ success: true, output: stdout.trim() || `Enforcement Executed: Blocked SSID '${ssid}' on macOS` });
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
        if (error) {
          resolve({ success: false, output: stderr || error.message });
        } else {
          resolve({ success: true, output: stdout.trim() || `Enforcement Executed: Blocked SSID '${ssid}' on Windows` });
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
          if (error) {
            if (ssid) {
              execFile('nmcli', ['connection', 'delete', ssid], (err2, out2, errOut2) => {
                if (err2) resolve({ success: false, output: errOut2 || err2.message });
                else resolve({ success: true, output: out2.trim() || `Enforcement Executed: Deleted connection '${ssid}' on Linux` });
              });
            } else {
              resolve({ success: false, output: stderr || error.message });
            }
          } else {
            resolve({ success: true, output: stdout.trim() || `Enforcement Executed: Blocked BSSID '${bssid}' on Linux` });
          }
        });
      } else if (ssid) {
        execFile('nmcli', ['connection', 'delete', ssid], (error, stdout, stderr) => {
          if (error) resolve({ success: false, output: stderr || error.message });
          else resolve({ success: true, output: stdout.trim() || `Enforcement Executed: Deleted connection '${ssid}' on Linux` });
        });
      } else {
        resolve({ success: false, output: "Invalid parameters for nmcli enforcement." });
      }
    }
  });
});
