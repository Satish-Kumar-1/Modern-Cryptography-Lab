import { contextBridge, ipcRenderer, shell } from "electron";

contextBridge.exposeInMainWorld("cryptoGuardDesktop", {
  isElectron: true,
  electronVersion: process.versions.electron,
  nodeVersion: process.versions.node,
  platform: process.platform,
  minimize: () => ipcRenderer.send("window-minimize"),
  maximize: () => ipcRenderer.send("window-maximize"),
  close: () => ipcRenderer.send("window-close")
});
