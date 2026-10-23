const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("pdfUtilsOnrWebPki", {
  listCertificates: () => ipcRenderer.invoke("certificates:list"),
  readCertificate: (payload) => ipcRenderer.invoke("webpki:read-certificate", payload),
  signData: (payload) => ipcRenderer.invoke("webpki:sign-data", payload),
  openInstaller: () => ipcRenderer.invoke("shell:open-external", "https://get.webpkiplugin.com/")
});
