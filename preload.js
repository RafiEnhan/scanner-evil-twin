const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegisairAPI', {
  onBackendEvent: (callback) => {
    ipcRenderer.on('backend-event', (event, data) => callback(data));
  },
  executeOsBan: (commandStr, payload) => {
    let banPayload = commandStr;
    if (typeof commandStr === 'string' && payload) {
      banPayload = { commandStr, ...payload };
    }
    return ipcRenderer.invoke('execute-os-ban', banPayload);
  }
});
