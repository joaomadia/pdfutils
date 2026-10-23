const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const { autoUpdater } = require("electron-updater");
const log = require("electron-log");
const crypto = require("crypto");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const http = require("http");
const { URL } = require("url");
const pdf = require("./core/pdf");
const signatureValidation = require("./core/signature-validation");
const webPkiNative = require("./core/webpki-native");
const onrApi = require("./core/onr-api");
const isSmokeTest = process.argv.includes("--smoke-test");
const APP_VERSION = app.getVersion();
const WEB_PKI_INSTALLER_URL = "https://get.webpkiplugin.com/";
const GHOSTSCRIPT_DOWNLOAD_PAGE_URL = "https://ghostscript.com/releases/gsdnld.html";
const GHOSTSCRIPT_RELEASES_API_URL = "https://api.github.com/repos/ArtifexSoftware/ghostpdl-downloads/releases/latest";
const ONR_API_BASE_URL = onrApi.DEFAULT_ONR_BASE_URL;
const ONR_PORTAL_URL = ONR_API_BASE_URL;
const ONR_AUTHORITY_URL = "https://auth.id.onr.org.br";
const ONR_DEFAULT_SUBSCRIPTION = "00000000-0000-0000-0000-000000000000";
const ONR_CONFIGURATION_ENDPOINT = "/api/configuration";
const ONR_LOGIN_PATH = "/private";
const ONR_OIDC_CLIENT_ID = "onr-assinador";
const ONR_OIDC_SCOPE = "openid profile preferred_username onr-assinador-api";
const ONR_OIDC_RESPONSE_TYPE = "id_token token";
const LEGACY_ASSINADOR_WEB_BASE_URL = "https://assinador-web.onr.org.br";
const LEGACY_ASSINADOR_ONR_BASE_URL = "https://assinador.onr.org.br";
const LEGACY_REGISTRO_IMOVEIS_BASE_URL = "https://assinador.registrodeimoveis.org.br";
const WEB_PKI_EXTENSION_IDS = [
  "dcngeagmmhegagicpcmpinaoklddcgon",
  "bbafmabaelnnkondpfpjmdklbmfnbmol"
];
const REST_PKI_CALLBACK_PATH = "/restpki-signature-callback";
const REST_PKI_CALLBACK_TIMEOUT_MS = onrApi.DEFAULT_SIGNATURE_TIMEOUT_MS;

autoUpdater.logger = log;
autoUpdater.autoDownload = true;
autoUpdater.autoInstallOnAppQuit = true;

let mainWindow = null;
let server = null;
let serverUrl = "";
let updateDownloaded = false;
const signatureJobs = new Map();
const workflowOperations = new Map();
const restPkiCallbacks = new Map();
let lastUpdateState = {
  status: "idle",
  percent: 0,
  message: "Aguardando verificação de atualizações."
};

const DEFAULT_CONFIG = {
  webPkiInstallerUrl: WEB_PKI_INSTALLER_URL,
  webPkiLicense: "",
  onrBaseUrl: ONR_API_BASE_URL,
  onrPortalUrl: ONR_PORTAL_URL,
  onrStartEndpoint: "/api/documents/fast-signature/certificate",
  onrCompleteEndpoint: "/api/documents/fast-signature",
  onrUploadBytesEndpoint: "/api/uploads/bytes",
  onrUseUploadBytes: false,
  onrSubscription: ONR_DEFAULT_SUBSCRIPTION,
  onrApiKey: "",
  onrBearerToken: "",
  onrCookieHeader: "",
  onrLoginStorageJson: "{}",
  onrExtraHeadersJson: "{}",
  onrOutputFolder: "",
  onrOrganizationId: null,
  onrFolderId: null,
  onrNewFolderName: null
};

function configPath() {
  return path.join(app.getPath("userData"), "config_pdfutils.json");
}

function configPaths() {
  const appData = app.getPath("appData");
  const candidates = [
    configPath(),
    path.join(appData, "PDFUtils", "config_pdfutils.json"),
    path.join(appData, "pdfutils", "config_pdfutils.json")
  ];
  const seen = new Set();
  return candidates.filter((candidate) => {
    const key = candidate.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeConfigForStorage(config = {}) {
  const merged = { ...DEFAULT_CONFIG, ...config };
  const urlKeys = ["webPkiInstallerUrl", "onrBaseUrl", "onrPortalUrl"];
  for (const key of urlKeys) {
    const value = String(merged[key] || "").trim();
    merged[key] = value || DEFAULT_CONFIG[key];
  }

  merged.onrBaseUrl = merged.onrBaseUrl.replace(/\/+$/, "");
  merged.onrPortalUrl = merged.onrPortalUrl.replace(/\/+$/, "");
  merged.onrBaseUrl = resolvedOnrBaseUrl(merged.onrBaseUrl);
  merged.onrPortalUrl = resolvedOnrPortalUrl(merged.onrPortalUrl);
  merged.onrStartEndpoint = String(merged.onrStartEndpoint || DEFAULT_CONFIG.onrStartEndpoint).trim() || DEFAULT_CONFIG.onrStartEndpoint;
  merged.onrCompleteEndpoint = String(merged.onrCompleteEndpoint || DEFAULT_CONFIG.onrCompleteEndpoint).trim() || DEFAULT_CONFIG.onrCompleteEndpoint;
  merged.onrUploadBytesEndpoint = String(merged.onrUploadBytesEndpoint || DEFAULT_CONFIG.onrUploadBytesEndpoint).trim() || DEFAULT_CONFIG.onrUploadBytesEndpoint;
  merged.onrUseUploadBytes = Boolean(merged.onrUseUploadBytes);
  merged.onrCookieHeader = String(merged.onrCookieHeader || "").trim();
  merged.onrLoginStorageJson = String(merged.onrLoginStorageJson || "{}").trim() || "{}";
  merged.onrExtraHeadersJson = String(merged.onrExtraHeadersJson || "{}").trim() || "{}";
  merged.onrOutputFolder = String(merged.onrOutputFolder || "").trim();
  return merged;
}

function readConfigFile(filePath) {
  try {
    return normalizeConfigForStorage(JSON.parse(fs.readFileSync(filePath, "utf8")));
  } catch (error) {
    log.warn(`Não foi possível carregar configurações de ${filePath}`, error);
    return null;
  }
}

function loadConfig() {
  const existingConfigs = configPaths()
    .filter((filePath) => fs.existsSync(filePath))
    .map((filePath) => ({ filePath, mtimeMs: fs.statSync(filePath).mtimeMs }))
    .sort((left, right) => right.mtimeMs - left.mtimeMs);

  for (const item of existingConfigs) {
    const loaded = readConfigFile(item.filePath);
    if (loaded) return loaded;
  }

  return normalizeConfigForStorage(DEFAULT_CONFIG);
}

function saveConfig(config) {
  const merged = normalizeConfigForStorage(config);
  const paths = configPaths();
  let primaryError = null;

  for (const filePath of paths) {
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify(merged, null, 2), "utf8");
    } catch (error) {
      log.warn(`Não foi possível salvar configurações em ${filePath}`, error);
      if (filePath === paths[0]) primaryError = error;
    }
  }

  if (primaryError) throw primaryError;
  return merged;
}

function onrHistoryPath() {
  return path.join(app.getPath("userData"), "onr_history.json");
}

function loadOnrHistory() {
  try {
    const filePath = onrHistoryPath();
    if (fs.existsSync(filePath)) {
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (Array.isArray(data)) return data;
    }
  } catch (error) {
    log.warn("Não foi possível carregar o histórico ONR", error);
  }
  return [];
}

function saveOnrHistory(items) {
  try {
    const filePath = onrHistoryPath();
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(Array.isArray(items) ? items : [], null, 2), "utf8");
    return true;
  } catch (error) {
    log.warn("Não foi possível salvar o histórico ONR", error);
    return false;
  }
}

function addOnrHistoryItem(item) {
  const history = loadOnrHistory();
  const newItem = {
    id: cryptoRandomId(),
    fileName: String(item.fileName || "").trim(),
    endpointLink: String(item.endpointLink || item.validationUrl || "").trim(),
    signedAt: item.signedAt || new Date().toISOString()
  };
  if (!newItem.fileName && !newItem.endpointLink) return history;
  history.unshift(newItem);
  saveOnrHistory(history);
  return history;
}

function resolvedOnrBaseUrl(value) {
  const text = normalizeUrl(value, DEFAULT_CONFIG.onrBaseUrl);
  return [LEGACY_ASSINADOR_ONR_BASE_URL, LEGACY_ASSINADOR_WEB_BASE_URL, LEGACY_REGISTRO_IMOVEIS_BASE_URL].includes(text)
    ? ONR_API_BASE_URL
    : text;
}

function resolvedOnrPortalUrl(value) {
  const text = normalizeUrl(value, DEFAULT_CONFIG.onrPortalUrl);
  return [LEGACY_ASSINADOR_ONR_BASE_URL, LEGACY_ASSINADOR_WEB_BASE_URL, LEGACY_REGISTRO_IMOVEIS_BASE_URL].includes(text)
    ? ONR_PORTAL_URL
    : text;
}

function compareVersionText(left, right) {
  const leftParts = String(left || "").split(".").map((part) => Number(part) || 0);
  const rightParts = String(right || "").split(".").map((part) => Number(part) || 0);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (leftParts[index] || 0) - (rightParts[index] || 0);
    if (diff) return diff;
  }
  return 0;
}

function browserUserDataRoots() {
  const localAppData = process.env.LOCALAPPDATA || "";
  if (!localAppData) return [];
  return [
    path.join(localAppData, "Google", "Chrome", "User Data"),
    path.join(localAppData, "Microsoft", "Edge", "User Data")
  ];
}

function webPkiExtensionCandidates() {
  const candidates = [];
  for (const root of browserUserDataRoots()) {
    if (!fs.existsSync(root)) continue;
    let profiles = [];
    try {
      profiles = fs.readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory());
    } catch (error) {
      log.warn(`Não foi possível listar perfis do navegador em ${root}`, error);
      continue;
    }

    for (const profile of profiles) {
      const extensionsRoot = path.join(root, profile.name, "Extensions");
      for (const extensionId of WEB_PKI_EXTENSION_IDS) {
        const extensionRoot = path.join(extensionsRoot, extensionId);
        if (!fs.existsSync(extensionRoot)) continue;
        let versions = [];
        try {
          versions = fs.readdirSync(extensionRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory());
        } catch (error) {
          log.warn(`Não foi possível listar versões da extensão Web PKI em ${extensionRoot}`, error);
          continue;
        }

        for (const versionDir of versions) {
          const extensionPath = path.join(extensionRoot, versionDir.name);
          const manifestPath = path.join(extensionPath, "manifest.json");
          if (!fs.existsSync(manifestPath)) continue;
          try {
            const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
            const name = String(manifest.name || "");
            const permissions = Array.isArray(manifest.permissions) ? manifest.permissions : [];
            if (!/web\s*(pki|signer)/i.test(name) || !permissions.includes("nativeMessaging")) continue;
            candidates.push({
              id: extensionId,
              name,
              version: manifest.version || versionDir.name.replace(/_.*$/, ""),
              path: extensionPath,
              profile: profile.name
            });
          } catch (error) {
            log.warn(`Não foi possível ler o manifesto da extensão em ${manifestPath}`, error);
          }
        }
      }
    }
  }

  return candidates.sort((left, right) => compareVersionText(right.version, left.version));
}

function stagedWebPkiExtensionPath(candidate) {
  const safeVersion = String(candidate.version || "0").replace(/[^0-9a-z._-]+/gi, "-");
  return path.join(app.getPath("userData"), "browser-extensions", `${candidate.id}-${safeVersion}`);
}

function stageWebPkiExtension(candidate) {
  const target = stagedWebPkiExtensionPath(candidate);
  const markerPath = path.join(target, ".pdfutils-source.txt");
  const marker = `${candidate.path}\n${candidate.version}`;

  try {
    if (fs.existsSync(markerPath) && fs.readFileSync(markerPath, "utf8") === marker) return target;
  } catch {}

  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.cpSync(candidate.path, target, {
    recursive: true,
    filter: (source) => path.basename(source) !== "_metadata"
  });
  fs.writeFileSync(markerPath, marker, "utf8");
  return target;
}

async function loadWebPkiExtensions(electronSession) {
  const candidates = webPkiExtensionCandidates();
  const loaded = [];
  const attemptedIds = new Set();

  for (const candidate of candidates) {
    if (attemptedIds.has(candidate.id)) continue;
    attemptedIds.add(candidate.id);
    try {
      const existing = typeof electronSession.getExtension === "function" ? electronSession.getExtension(candidate.id) : null;
      if (existing) {
        loaded.push({ ...candidate, loaded: true, alreadyLoaded: true });
        continue;
      }

      let extension = null;
      try {
        extension = await electronSession.loadExtension(candidate.path, { allowFileAccess: true });
      } catch (originalError) {
        const stagedPath = stageWebPkiExtension(candidate);
        extension = await electronSession.loadExtension(stagedPath, { allowFileAccess: true });
      }
      loaded.push({ ...candidate, loaded: true, loadedId: extension.id });
      log.info(`Extensao ${candidate.name} ${candidate.version} carregada para Login ONR: ${candidate.path}`);
    } catch (error) {
      loaded.push({ ...candidate, loaded: false, error: error.message || String(error) });
      log.warn(`Não foi possível carregar a extensão ${candidate.name} de ${candidate.path}`, error);
    }
  }

  if (!loaded.some((item) => item.loaded)) {
    log.warn("Nenhuma extensão Web PKI/Web Signer foi carregada na janela de Login ONR.", loaded);
  }

  return loaded;
}

function ghostscriptStatus() {
  const executable = pdf.findGhostscript();
  return {
    installed: Boolean(executable),
    executable: executable || "",
    version: executable ? pdf.ghostscriptVersion(executable) : "",
    downloadPageUrl: GHOSTSCRIPT_DOWNLOAD_PAGE_URL
  };
}

function sendDependencyProgress(sender, message) {
  if (!sender || sender.isDestroyed()) return;
  sender.send("dependencies:progress", message);
}

async function latestGhostscriptInstaller() {
  const response = await fetch(GHOSTSCRIPT_RELEASES_API_URL, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": `PDFUtils/${APP_VERSION}`
    }
  });
  if (!response.ok) throw new Error(`GitHub respondeu HTTP ${response.status} ao consultar o Ghostscript.`);

  const release = await response.json();
  const assets = Array.isArray(release.assets) ? release.assets : [];
  const installer = assets.find((asset) => /^gs\d+w64\.exe$/i.test(asset.name || ""))
    || assets.find((asset) => /w64\.exe$/i.test(asset.name || "") && /ghost|gs/i.test(asset.name || ""));

  if (!installer?.browser_download_url) {
    throw new Error("Não foi encontrado um instalador Windows x64 do Ghostscript na versão oficial.");
  }

  return {
    name: installer.name,
    url: installer.browser_download_url,
    size: Number(installer.size) || 0,
    digest: installer.digest || "",
    releaseName: release.name || release.tag_name || installer.name
  };
}

function verifyInstallerDigest(filePath, digest) {
  const expected = String(digest || "").trim();
  if (!expected.toLowerCase().startsWith("sha256:")) return;
  const hash = crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  const expectedHash = expected.slice("sha256:".length).toLowerCase();
  if (hash !== expectedHash) throw new Error("O instalador baixado do Ghostscript não passou na verificação SHA-256.");
}

async function downloadGhostscriptInstaller(installer, sender) {
  const dependenciesDir = path.join(app.getPath("userData"), "dependencies");
  fs.mkdirSync(dependenciesDir, { recursive: true });
  const safeName = path.basename(installer.name).replace(/[<>:"/\\|?*]+/g, "-");
  const outputPath = path.join(dependenciesDir, safeName);

  if (fs.existsSync(outputPath) && (!installer.size || fs.statSync(outputPath).size === installer.size)) {
    verifyInstallerDigest(outputPath, installer.digest);
    return outputPath;
  }

  const tempPath = `${outputPath}.download`;
  fs.rmSync(tempPath, { force: true });
  sendDependencyProgress(sender, `Baixando instalador oficial do Ghostscript (${installer.releaseName})...`);
  const response = await fetch(installer.url, {
    headers: {
      Accept: "application/octet-stream",
      "User-Agent": `PDFUtils/${APP_VERSION}`
    }
  });
  if (!response.ok) throw new Error(`Falha ao baixar Ghostscript: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(tempPath, bytes);
  verifyInstallerDigest(tempPath, installer.digest);
  fs.renameSync(tempPath, outputPath);
  return outputPath;
}

async function openGhostscriptInstaller(installerPath) {
  const result = await shell.openPath(installerPath);
  if (result) {
    throw new Error(`Não foi possível abrir o instalador do Ghostscript: ${result}`);
  }
}

async function installGhostscript(sender, options = {}) {
  const current = ghostscriptStatus();
  if (current.installed) return { ...current, launched: false, canceled: false };

  if (options.confirm) {
    const answer = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Baixar e abrir instalador", "Cancelar"],
      defaultId: 0,
      cancelId: 1,
      message: "Ghostscript não encontrado",
      detail: "O Ghostscript é necessário para converter documentos em PDF/A. O PDFUtils pode baixar o instalador oficial da Artifex e abrir a instalação agora."
    });
    if (answer.response !== 0) return { ...current, launched: false, canceled: true };
  }

  sendDependencyProgress(sender, "Consultando release oficial do Ghostscript...");
  const installer = await latestGhostscriptInstaller();
  const installerPath = await downloadGhostscriptInstaller(installer, sender);
  sendDependencyProgress(sender, "Abrindo instalador do Ghostscript...");
  await openGhostscriptInstaller(installerPath);
  return {
    ...ghostscriptStatus(),
    launched: true,
    canceled: false,
    installerPath,
    releaseName: installer.releaseName,
    message: "Instalador do Ghostscript aberto. Conclua a instalação e tente novamente."
  };
}

function mergeConfigFromPayload(payloadConfig = {}) {
  const saved = loadConfig();
  const merged = { ...saved, ...payloadConfig };
  if (!String(payloadConfig.webPkiLicense || "").trim() && String(saved.webPkiLicense || "").trim()) {
    merged.webPkiLicense = saved.webPkiLicense;
  }
  return merged;
}

function mimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") return "text/html; charset=utf-8";
  if (ext === ".css") return "text/css; charset=utf-8";
  if (ext === ".js") return "text/javascript; charset=utf-8";
  if (ext === ".png") return "image/png";
  if (ext === ".svg") return "image/svg+xml";
  if (ext === ".ico") return "image/x-icon";
  return "application/octet-stream";
}

function finishRestPkiCallback(state, payload, error = null) {
  const callback = restPkiCallbacks.get(state);
  if (!callback) return;
  clearTimeout(callback.timeout);
  restPkiCallbacks.delete(state);
  if (error) {
    callback.reject(error);
    return;
  }
  callback.resolve(payload);
}

function cancelRestPkiCallback(state) {
  const callback = restPkiCallbacks.get(state);
  if (!callback) return;
  clearTimeout(callback.timeout);
  restPkiCallbacks.delete(state);
}

function handleRestPkiCallback(requestUrl, res) {
  if (requestUrl.pathname !== REST_PKI_CALLBACK_PATH) return false;

  const state = requestUrl.searchParams.get("state") || "";
  const signatureSessionId = requestUrl.searchParams.get("signatureSessionId") || "";
  const status = requestUrl.searchParams.get("status") || "";
  const errorMessage = signatureSessionId
    ? ""
    : "Assinatura ONR cancelada ou retorno sem signatureSessionId.";

  if (state) {
    finishRestPkiCallback(
      state,
      { signatureSessionId, status },
      errorMessage ? new Error(errorMessage) : null
    );
  }

  const title = signatureSessionId ? "Assinatura recebida" : "Assinatura não concluída";
  const message = signatureSessionId
    ? "O PDFUtils recebeu o retorno da assinatura. Esta janela pode ser fechada."
    : "Não foi possível concluir o retorno da assinatura. Volte ao PDFUtils para ver os detalhes.";

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(`<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 48px; color: #281113; background: #f7f3f3; }
    main { max-width: 560px; margin: 0 auto; padding: 28px; background: #fff; border: 1px solid #eadada; border-radius: 8px; }
    h1 { font-size: 24px; margin: 0 0 12px; }
    p { font-size: 16px; line-height: 1.5; }
  </style>
</head>
<body>
  <main>
    <h1>${title}</h1>
    <p>${message}</p>
  </main>
</body>
</html>`);
  return true;
}

async function createRestPkiCallback() {
  if (!serverUrl) await startLocalServer();
  const state = cryptoRandomId();
  let timeout = null;
  const promise = new Promise((resolve, reject) => {
    timeout = setTimeout(() => {
      restPkiCallbacks.delete(state);
      reject(new Error("Tempo esgotado aguardando retorno da assinatura ONR."));
    }, REST_PKI_CALLBACK_TIMEOUT_MS);
    restPkiCallbacks.set(state, { resolve, reject, timeout });
  });

  return {
    state,
    returnUrl: `${serverUrl}${REST_PKI_CALLBACK_PATH}?state=${encodeURIComponent(state)}`,
    promise
  };
}

function startLocalServer() {
  const rendererRoot = path.join(__dirname, "renderer");

  server = http.createServer((req, res) => {
    try {
      const requestUrl = new URL(req.url, "http://127.0.0.1");
      if (handleRestPkiCallback(requestUrl, res)) return;
      const safePath = requestUrl.pathname === "/" ? "/index.html" : decodeURIComponent(requestUrl.pathname);
      const normalized = path.normalize(safePath).replace(/^(\.\.[/\\])+/, "");
      const target = path.join(rendererRoot, normalized);
      if (!target.startsWith(rendererRoot) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Not found");
        return;
      }
      res.writeHead(200, {
        "Content-Type": mimeType(target),
        "Cache-Control": "no-store"
      });
      fs.createReadStream(target).pipe(res);
    } catch (error) {
      res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      res.end(error.message || "Erro interno");
    }
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      serverUrl = `http://127.0.0.1:${address.port}`;
      resolve(serverUrl);
    });
  });
}

function sendUpdateState(win, state) {
  if (!win || win.isDestroyed() || win.webContents.isDestroyed()) return;
  win.webContents.send("update:status", state);
}

function publishUpdateState(state) {
  lastUpdateState = { ...lastUpdateState, ...state, timestamp: Date.now() };
  for (const win of BrowserWindow.getAllWindows()) sendUpdateState(win, lastUpdateState);
}

function setupAutoUpdater() {
  if (!app.isPackaged || isSmokeTest) {
    publishUpdateState({
      status: "disabled",
      percent: 0,
      message: "Atualizacao automatica ativa apenas no app instalado."
    });
    return;
  }

  autoUpdater.on("checking-for-update", () => {
    publishUpdateState({ status: "checking", percent: 8, message: "Consultando atualizações no GitHub..." });
  });
  autoUpdater.on("update-available", (info) => {
    publishUpdateState({ status: "available", percent: 12, version: info.version, message: `Versao ${info.version} encontrada.` });
  });
  autoUpdater.on("download-progress", (progress) => {
    const percent = Math.max(0, Math.min(100, Number(progress.percent) || 0));
    publishUpdateState({ status: "downloading", percent, message: `Baixando atualizacao (${Math.round(percent)}%).` });
  });
  autoUpdater.on("update-downloaded", (info) => {
    updateDownloaded = true;
    publishUpdateState({ status: "downloaded", percent: 100, version: info.version, canInstall: true, message: `Versao ${info.version} baixada.` });
  });
  autoUpdater.on("update-not-available", () => {
    publishUpdateState({ status: "not-available", percent: 100, version: APP_VERSION, message: `Voce ja esta na versao ${APP_VERSION}.` });
  });
  autoUpdater.on("error", (error) => {
    publishUpdateState({ status: "error", percent: 100, message: `Falha ao verificar atualizações: ${error.message || error}` });
  });

  autoUpdater.checkForUpdates().catch(() => {});
}

async function createWindow() {
  if (!serverUrl) await startLocalServer();

  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 980,
    minHeight: 640,
    title: `PDFUtils v${APP_VERSION}`,
    icon: path.join(__dirname, "renderer", "assets", "logo.png"),
    backgroundColor: "#f5f6f8",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.loadURL(serverUrl);
  mainWindow.webContents.once("did-finish-load", () => sendUpdateState(mainWindow, lastUpdateState));
  if (isSmokeTest) {
    mainWindow.webContents.once("did-finish-load", () => setTimeout(() => app.quit(), 700));
  }
}

function saveErrorLog(error, context = {}) {
  const logsDir = path.join(app.getPath("userData"), "logs");
  fs.mkdirSync(logsDir, { recursive: true });
  const logPath = path.join(logsDir, `pdfutils-${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  const payload = [
    `PDFUtils v${APP_VERSION}`,
    `Data: ${new Date().toISOString()}`,
    "",
    "Contexto:",
    JSON.stringify(context, null, 2),
    "",
    "Erro:",
    error && error.stack ? error.stack : String(error && error.message ? error.message : error)
  ].join("\n");
  fs.writeFileSync(logPath, payload, "utf8");
  return logPath;
}

function normalizeUrl(value, fallback) {
  const text = String(value || fallback).trim().replace(/\/+$/, "");
  return text || fallback;
}

function normalizeApiBaseUrl(value) {
  return resolvedOnrBaseUrl(value);
}

function normalizePortalUrl(value) {
  return resolvedOnrPortalUrl(value);
}

function endpointUrl(config, endpoint) {
  const base = normalizeApiBaseUrl(config.onrBaseUrl);
  const target = String(endpoint || "").trim();
  if (/^https?:\/\//i.test(target)) return target;
  return `${base}${target.startsWith("/") ? "" : "/"}${target}`;
}

function onrLoginUrl(config) {
  return `${normalizeApiBaseUrl(config.onrBaseUrl)}${ONR_LOGIN_PATH}`;
}

function onrLoginOrigin(config) {
  return new URL(normalizeApiBaseUrl(config.onrBaseUrl)).origin;
}

function configurationUrl(baseUrl) {
  const base = normalizeUrl(baseUrl, ONR_API_BASE_URL);
  return `${base}${ONR_CONFIGURATION_ENDPOINT}`;
}

async function fetchWebPkiLicenseFrom(baseUrl) {
  const response = await fetch(configurationUrl(baseUrl), {
    headers: { Accept: "application/json, text/plain, */*" }
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  const license = String(data?.webPki?.license || "").trim();
  if (!license) throw new Error("Configuração sem licença Web PKI.");
  return license;
}

async function fetchDefaultWebPkiLicense(config) {
  const candidates = [
    normalizeApiBaseUrl(config.onrBaseUrl),
    normalizePortalUrl(config.onrPortalUrl),
    ONR_API_BASE_URL,
    ONR_PORTAL_URL
  ];
  let lastError = null;
  for (const baseUrl of [...new Set(candidates)]) {
    try {
      return await fetchWebPkiLicenseFrom(baseUrl);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("Não foi possível obter a licença Web PKI.");
}

async function ensureWebPkiLicense(config, options = {}) {
  const current = String(config.webPkiLicense || "").trim();
  if (current && !options.force) return config;
  const license = await fetchDefaultWebPkiLicense(config);
  return saveConfig({ ...config, webPkiLicense: license });
}

function isWebPkiLicenseError(error) {
  const message = String(error?.message || error || "");
  return error?.code === "license_invalid" || /invalid license|license_invalid|licen[cç]a.*web pki/i.test(message);
}

async function runWebPkiWithAutoLicense(config, action) {
  let resolvedConfig = config;
  try {
    resolvedConfig = await ensureWebPkiLicense(config);
  } catch (error) {
    if (!String(config.webPkiLicense || "").trim()) {
      const friendly = new Error("Licença Web PKI ausente ou inválida. O app tentou buscar a licença do ONR automaticamente; confira sua conexão e tente novamente.");
      friendly.cause = error;
      throw friendly;
    }
  }

  try {
    return await action(resolvedConfig);
  } catch (error) {
    if (!isWebPkiLicenseError(error)) throw error;
    try {
      const refreshedConfig = await ensureWebPkiLicense(config, { force: true });
      return await action(refreshedConfig);
    } catch (retryError) {
      if (!isWebPkiLicenseError(retryError)) throw retryError;
      const friendly = new Error("Licença Web PKI ausente ou inválida. O app tentou buscar a licença do ONR automaticamente; confira sua conexão e tente novamente.");
      friendly.cause = retryError;
      throw friendly;
    }
  }
}

function normalizeBearerToken(token) {
  return String(token || "").replace(/^Bearer\s+/i, "").trim();
}

function oauthDateFromMs(value) {
  const ms = Number(value || 0);
  if (!Number.isFinite(ms) || ms <= 0) return "";
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function randomOAuthValue() {
  return crypto.randomBytes(24).toString("base64url");
}

function onrAuthorizeUrl(config) {
  const params = new URLSearchParams({
    response_type: ONR_OIDC_RESPONSE_TYPE,
    client_id: ONR_OIDC_CLIENT_ID,
    scope: ONR_OIDC_SCOPE,
    redirect_uri: normalizePortalUrl(config.onrPortalUrl),
    state: randomOAuthValue(),
    nonce: randomOAuthValue()
  });
  return `${ONR_AUTHORITY_URL}/connect/authorize?${params.toString()}`;
}

function splitSetCookieHeader(value) {
  if (!value) return [];
  return String(value)
    .split(/,(?=\s*[^;,=\s]+=)/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function setCookieHeaders(response) {
  if (typeof response.headers.getSetCookie === "function") return response.headers.getSetCookie();
  if (typeof response.headers.raw === "function") return response.headers.raw()["set-cookie"] || [];
  return splitSetCookieHeader(response.headers.get("set-cookie"));
}

class HttpCookieJar {
  constructor() {
    this.cookiesByHost = new Map();
  }

  store(url, response) {
    const host = new URL(url).hostname.toLowerCase();
    if (!this.cookiesByHost.has(host)) this.cookiesByHost.set(host, new Map());
    const cookies = this.cookiesByHost.get(host);
    for (const item of setCookieHeaders(response)) {
      const pair = String(item).split(";")[0];
      const separator = pair.indexOf("=");
      if (separator <= 0) continue;
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      if (!value && /max-age=0|expires=/i.test(item)) cookies.delete(name);
      else cookies.set(name, `${name}=${value}`);
    }
  }

  header(url) {
    const host = new URL(url).hostname.toLowerCase();
    const cookies = this.cookiesByHost.get(host);
    return cookies ? Array.from(cookies.values()).join("; ") : "";
  }
}

async function fetchWithCookieJar(jar, url, options = {}) {
  const headers = { ...(options.headers || {}) };
  const cookieHeader = jar.header(url);
  if (cookieHeader) headers.Cookie = cookieHeader;
  const response = await fetch(url, {
    ...options,
    headers,
    redirect: "manual"
  });
  jar.store(url, response);
  return response;
}

function absoluteUrl(location, baseUrl) {
  return new URL(location, baseUrl).href;
}

function redirectUrlFromResponse(response, currentUrl) {
  const location = response.headers.get("location");
  return location ? absoluteUrl(location, currentUrl) : "";
}

function decodeHtmlAttribute(value) {
  return String(value || "")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#x([0-9a-f]+);/gi, (_match, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_match, number) => String.fromCharCode(parseInt(number, 10)));
}

function htmlAttribute(tag, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const regex = new RegExp(`\\b${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const match = regex.exec(tag);
  return decodeHtmlAttribute(match ? (match[1] ?? match[2] ?? match[3] ?? "") : "");
}

function extractFormInputs(html) {
  const values = {};
  const inputRegex = /<input\b[^>]*>/gi;
  let match;
  while ((match = inputRegex.exec(html))) {
    const tag = match[0];
    const name = htmlAttribute(tag, "name");
    if (!name) continue;
    values[name] = htmlAttribute(tag, "value");
  }
  return values;
}

function extractCertificateLoginUrl(loginHtml, baseUrl) {
  const linkRegex = /<a\b[^>]*>/gi;
  let match;
  while ((match = linkRegex.exec(loginHtml))) {
    const href = htmlAttribute(match[0], "href");
    if (/\/Account\/CertificateLogin/i.test(href)) return absoluteUrl(href, baseUrl);
  }
  return "";
}

function extractCertificateFormAction(certificateHtml, baseUrl) {
  const formRegex = /<form\b[^>]*>/gi;
  let match;
  while ((match = formRegex.exec(certificateHtml))) {
    const tag = match[0];
    const id = htmlAttribute(tag, "id");
    if (id && id !== "signInForm") continue;
    const action = htmlAttribute(tag, "action");
    if (action) return absoluteUrl(action, baseUrl);
  }
  return "";
}

function extractPlainTextFromHtml(html) {
  return decodeHtmlAttribute(String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim());
}

function webPkiStringResult(value, keys = []) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "";
  for (const key of keys) {
    if (typeof value[key] === "string" && value[key]) return value[key];
  }
  return "";
}

function certificateContentFromWebPki(value) {
  const content = webPkiStringResult(value, ["certificate", "content", "encodedCertificate", "value"]);
  return String(content || "")
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "")
    .trim();
}

function onrTokenFromRedirectUrl(value) {
  const text = String(value || "");
  const hashIndex = text.indexOf("#");
  if (hashIndex < 0) return null;
  const params = new URLSearchParams(text.slice(hashIndex + 1));
  const accessToken = normalizeBearerToken(params.get("access_token"));
  if (!accessToken) return null;
  const expiresIn = Number(params.get("expires_in") || 0);
  const expiresAt = Number.isFinite(expiresIn) && expiresIn > 0
    ? new Date(Date.now() + expiresIn * 1000).toISOString()
    : "";
  return {
    accessToken,
    expiresAt,
    href: text,
    idToken: params.get("id_token") || "",
    storage: {
      nativeCertificateLogin: true,
      tokenType: params.get("token_type") || "",
      state: params.get("state") || ""
    }
  };
}

async function followOnrLoginRedirects(jar, response, currentUrl) {
  let activeResponse = response;
  let activeUrl = currentUrl;
  for (let attempt = 0; attempt < 15; attempt += 1) {
    if (activeResponse.status >= 300 && activeResponse.status < 400) {
      const nextUrl = redirectUrlFromResponse(activeResponse, activeUrl);
      if (!nextUrl) throw new Error("Login ONR não retornou redirecionamento.");
      const token = onrTokenFromRedirectUrl(nextUrl);
      if (token) return token;
      activeUrl = nextUrl;
      activeResponse = await fetchWithCookieJar(jar, activeUrl, {
        method: "GET",
        headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }
      });
      continue;
    }

    const token = onrTokenFromRedirectUrl(activeResponse.url || activeUrl);
    if (token) return token;
    const text = await activeResponse.text().catch(() => "");
    const summary = extractPlainTextFromHtml(text).slice(0, 400);
    throw new Error(summary || `Login ONR parou em HTTP ${activeResponse.status}.`);
  }
  throw new Error("Login ONR excedeu o limite de redirecionamentos.");
}

async function registerOnrProfile(config) {
  try {
    await postJsonToOnr(config, "/api/register", null);
  } catch (error) {
    log.warn("Não foi possível registrar ou confirmar o perfil ONR após o login", error);
  }
}

async function loginToOnrWithCertificate(config, certificateThumbprint) {
  const thumbprint = String(certificateThumbprint || "").trim();
  if (!thumbprint) throw new Error("Selecione um certificado digital válido para autenticar na ONR.");

  const jar = new HttpCookieJar();
  const authorizeUrl = onrAuthorizeUrl(config);
  const loginStartResponse = await fetchWithCookieJar(jar, authorizeUrl, {
    method: "GET",
    headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }
  });
  const loginStartUrl = redirectUrlFromResponse(loginStartResponse, authorizeUrl);
  if (!loginStartUrl) throw new Error("Login ONR não retornou a tela de autenticação.");

  const loginResponse = await fetchWithCookieJar(jar, loginStartUrl, {
    method: "GET",
    headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }
  });
  const loginHtml = await loginResponse.text();
  const certificateLoginUrl = extractCertificateLoginUrl(loginHtml, loginStartUrl);
  if (!certificateLoginUrl) throw new Error("Login ONR não ofereceu acesso com certificado.");

  const certificateResponse = await fetchWithCookieJar(jar, certificateLoginUrl, {
    method: "GET",
    headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }
  });
  const certificateHtml = await certificateResponse.text();
  const fields = extractFormInputs(certificateHtml);
  const challenge = fields.Challenge || "";
  const digestAlgorithm = fields.DigestAlgorithm || "SHA-256";
  const formAction = extractCertificateFormAction(certificateHtml, certificateLoginUrl);
  if (!challenge || !formAction || !fields.__RequestVerificationToken) {
    throw new Error("Login ONR não retornou um desafio de certificado válido.");
  }

  const webPkiDomain = new URL(ONR_AUTHORITY_URL).hostname;
  const certificateResult = await runWebPkiWithAutoLicense(config, (resolvedConfig) => (
    webPkiNative.readCertificate({ ...resolvedConfig, webPkiDomain }, thumbprint)
  ));
  const signatureResult = await runWebPkiWithAutoLicense(config, (resolvedConfig) => (
    webPkiNative.signData({ ...resolvedConfig, webPkiDomain }, {
      thumbprint,
      data: challenge,
      digestAlgorithm
    })
  ));
  const certificate = webPkiStringResult(certificateResult, ["certificate", "certificateContent", "content"]);
  const signature = webPkiStringResult(signatureResult, ["signature", "value", "signedData"]);
  if (!certificate || !signature) throw new Error("O Web PKI não retornou o certificado ou a assinatura para o login ONR.");

  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) form.set(key, value);
  form.set("Certificate", certificate);
  form.set("Signature", signature);

  const postResponse = await fetchWithCookieJar(jar, formAction, {
    method: "POST",
    headers: {
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Content-Type": "application/x-www-form-urlencoded",
      "Origin": ONR_AUTHORITY_URL,
      "Referer": certificateLoginUrl
    },
    body: form.toString()
  });
  const token = await followOnrLoginRedirects(jar, postResponse, formAction);
  const nextConfig = saveConfig({
    ...config,
    onrBearerToken: token.accessToken,
    onrCookieHeader: "",
    onrLoginStorageJson: JSON.stringify({
      href: token.href,
      expiresAt: token.expiresAt,
      idToken: token.idToken,
      storage: token.storage
    })
  });
  await registerOnrProfile(nextConfig);
  return { ...token, cookieHeader: "", config: nextConfig };
}

async function extractOnrAccessToken(loginWindow, expectedOrigin) {
  if (!loginWindow || loginWindow.isDestroyed()) return null;
  const currentUrl = loginWindow.webContents.getURL();
  let currentOrigin = "";
  try {
    currentOrigin = new URL(currentUrl).origin;
  } catch {
    return null;
  }
  if (currentOrigin !== expectedOrigin) return null;

  const tokenData = await loginWindow.webContents.executeJavaScript(`
    (() => {
      const readStore = (store) => {
        const values = {};
        for (let index = 0; index < store.length; index += 1) {
          const key = store.key(index);
          values[key] = store.getItem(key);
        }
        return values;
      };
      const readParams = (value) => {
        const values = {};
        const text = String(value || "").replace(/^[?#]/, "");
        const params = new URLSearchParams(text);
        for (const [key, item] of params.entries()) values[key] = item;
        return values;
      };
      const pick = (...sources) => {
        for (const source of sources) {
          if (!source) continue;
          if (source.access_token) return source.access_token;
          const key = Object.keys(source).find((item) => /access.*token/i.test(item));
          if (key && source[key]) return source[key];
        }
        return "";
      };
      const session = readStore(sessionStorage);
      const local = readStore(localStorage);
      const hash = readParams(location.hash);
      const search = readParams(location.search);
      const accessToken = pick(session, local, hash, search);
      return {
        href: location.href,
        accessToken,
        expiresAt: session.expires_at || local.expires_at || hash.expires_at || search.expires_at || "",
        idToken: session.id_token || local.id_token || hash.id_token || search.id_token || "",
        session,
        local
      };
    })();
  `, true);

  const accessToken = normalizeBearerToken(tokenData?.accessToken);
  if (!accessToken) return null;
  return {
    accessToken,
    expiresAt: oauthDateFromMs(tokenData.expiresAt),
    href: tokenData.href || currentUrl,
    idToken: tokenData.idToken || "",
    storage: {
      session: tokenData.session || {},
      local: tokenData.local || {}
    }
  };
}

async function onrCookieHeaderFromSession(config, electronSession) {
  if (!electronSession) return "";
  const urls = [...new Set([normalizeApiBaseUrl(config.onrBaseUrl), ONR_API_BASE_URL])];
  const byName = new Map();
  for (const url of urls) {
    try {
      const cookies = await electronSession.cookies.get({ url });
      for (const cookie of cookies) {
        if (!cookie.name || typeof cookie.value !== "string") continue;
        byName.set(cookie.name, `${cookie.name}=${cookie.value}`);
      }
    } catch (error) {
      log.warn(`Falha ao ler cookies ONR de ${url}`, error);
    }
  }
  return Array.from(byName.values()).join("; ");
}

function onrWebPkiBridgeScript() {
  return `
    (() => {
      if (!/\\/Account\\/CertificateLogin/i.test(location.pathname)) return false;
      const bridge = window.pdfUtilsOnrWebPki;
      if (!bridge) return false;

      const asError = (error) => ({
        userMessage: error && error.message ? error.message : String(error || "Erro no Web PKI"),
        error
      });
      let defaultFail = null;
      const wrap = (promise) => {
        Promise.resolve(promise).catch((error) => {
          if (typeof defaultFail === "function") defaultFail(asError(error));
        });
        const chain = {
          success(callback) {
            Promise.resolve(promise).then((value) => {
              if (typeof callback === "function") callback(value);
            });
            return chain;
          },
          fail(callback) {
            Promise.resolve(promise).catch((error) => {
              if (typeof callback === "function") callback(asError(error));
            });
            return chain;
          },
          error(callback) {
            return chain.fail(callback);
          }
        };
        return chain;
      };
      const normalizeCert = (cert) => ({
        ...cert,
        validityStart: cert && cert.validityStart ? new Date(cert.validityStart) : null,
        validityEnd: cert && cert.validityEnd ? new Date(cert.validityEnd) : null
      });
      const defaultText = (cert) => {
        const name = cert.subjectName || cert.subjectDN || "Certificado";
        const issuer = cert.issuerName || cert.issuerDN || "";
        return issuer ? name + " (" + issuer + ")" : name;
      };
      const fillSelect = (options, certs) => {
        if (!options || !options.selectId) return;
        const select = document.getElementById(options.selectId);
        if (!select) return;
        select.innerHTML = "";
        for (const cert of certs) {
          const option = document.createElement("option");
          option.value = cert.thumbprint || "";
          option.textContent = typeof options.selectOptionFormatter === "function"
            ? options.selectOptionFormatter(cert)
            : defaultText(cert);
          select.appendChild(option);
        }
      };

      function PdfUtilsWebPki(license) {
        this.license = license || "";
        this.isSupportedMobile = false;
        this._supportedMobileDetected = false;
      }

      PdfUtilsWebPki.prototype.init = function init(options) {
        defaultFail = options && typeof options.defaultFail === "function" ? options.defaultFail : null;
        setTimeout(() => {
          if (options && typeof options.ready === "function") options.ready();
        }, 0);
        return wrap(Promise.resolve(true));
      };
      PdfUtilsWebPki.prototype.listCertificates = function listCertificates(options) {
        const promise = bridge.listCertificates().then((items) => {
          let certs = Array.isArray(items) ? items.map(normalizeCert) : [];
          if (options && typeof options.filter === "function") {
            certs = certs.filter((cert) => options.filter(cert));
          }
          fillSelect(options, certs);
          return certs;
        });
        return wrap(promise);
      };
      PdfUtilsWebPki.prototype.readCertificate = function readCertificate(thumbprint) {
        return wrap(bridge.readCertificate({
          thumbprint,
          webPkiDomain: location.hostname
        }));
      };
      PdfUtilsWebPki.prototype.signData = function signData(options) {
        return wrap(bridge.signData({
          thumbprint: options && options.thumbprint,
          data: options && options.data,
          digestAlgorithm: options && options.digestAlgorithm,
          webPkiDomain: location.hostname
        }));
      };
      PdfUtilsWebPki.prototype.redirectToInstallPage = function redirectToInstallPage() {
        bridge.openInstaller();
      };

      window.LacunaWebPKI = PdfUtilsWebPki;
      window.pki = new PdfUtilsWebPki(window.pkiLicense || "");
      if (window.$ && window.$.unblockUI) window.$.unblockUI();
      if (typeof window.blockScreen === "function") window.blockScreen();
      if (typeof window.loadCertificates === "function") window.loadCertificates();
      return true;
    })();
  `;
}

async function injectOnrWebPkiBridge(loginWindow) {
  if (!loginWindow || loginWindow.isDestroyed()) return;
  const currentUrl = loginWindow.webContents.getURL();
  if (!/^https:\/\/auth\.id\.onr\.org\.br\/Account\/CertificateLogin/i.test(currentUrl)) return;
  await loginWindow.webContents.executeJavaScript(onrWebPkiBridgeScript(), true);
}

function loginToOnrWithWindow(config) {
  return new Promise((resolve, reject) => {
    const expectedOrigin = onrLoginOrigin(config);
    const loginPartition = "persist:pdfutils-onr-login";
    const loginWindows = new Set();
    const loginWindow = new BrowserWindow({
      width: 1120,
      height: 780,
      minWidth: 900,
      minHeight: 640,
      title: "Login ONR",
      parent: mainWindow || undefined,
      autoHideMenuBar: true,
      backgroundColor: "#1f1717",
      webPreferences: {
        preload: path.join(__dirname, "onr-login-preload.js"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: false,
        partition: loginPartition
      }
    });

    let settled = false;
    let timer = null;

    const finish = (error, result = null) => {
      if (settled) return;
      settled = true;
      if (timer) clearInterval(timer);
      for (const win of loginWindows) {
        if (!win.isDestroyed()) win.close();
      }
      if (error) reject(error);
      else resolve(result);
    };

    const loadError = (errorCode, errorDescription, validatedURL) => {
      const message = `Não foi possível carregar o login ONR (${errorCode}: ${errorDescription || "erro desconhecido"}). URL: ${validatedURL || onrLoginUrl(config)}`;
      const error = new Error(message);
      error.code = errorCode;
      finish(error);
    };

    const checkToken = async () => {
      if (settled || loginWindow.isDestroyed()) return;
      for (const win of loginWindows) {
        if (settled || win.isDestroyed()) continue;
        try {
          const token = await extractOnrAccessToken(win, expectedOrigin);
          if (!token) continue;
          const cookieHeader = await onrCookieHeaderFromSession(config, win.webContents.session);
          const nextConfig = saveConfig({
            ...config,
            onrBearerToken: token.accessToken,
            onrCookieHeader: cookieHeader,
            onrLoginStorageJson: JSON.stringify({
              href: token.href,
              expiresAt: token.expiresAt,
              idToken: token.idToken,
              storage: token.storage
            })
          });
          finish(null, { ...token, cookieHeader, config: nextConfig });
          return;
        } catch (error) {
          log.warn("Falha ao tentar capturar token ONR", error);
        }
      }
    };

    const wireLoginWindow = (win) => {
      loginWindows.add(win);
      const webContents = win.webContents;
      const userAgent = webContents.getUserAgent().replace(/\sElectron\/\S+/i, "");
      webContents.setUserAgent(userAgent);
      webContents.on("did-finish-load", () => {
        checkToken();
        injectOnrWebPkiBridge(win).catch((error) => log.warn("Falha ao instalar ponte Web PKI na tela ONR", error));
      });
      webContents.on("dom-ready", checkToken);
      webContents.on("did-navigate", checkToken);
      webContents.on("did-navigate-in-page", checkToken);
      webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
        if (isMainFrame && errorCode !== -3) loadError(errorCode, errorDescription, validatedURL);
      });
      webContents.on("did-fail-provisional-load", (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
        if (isMainFrame && errorCode !== -3) loadError(errorCode, errorDescription, validatedURL);
      });
      webContents.on("console-message", (_event, level, message, line, sourceId) => {
        if (level >= 2) log.warn(`Login ONR console: ${message} (${sourceId}:${line})`);
      });
      webContents.setWindowOpenHandler(() => ({
        action: "allow",
        overrideBrowserWindowOptions: {
          parent: win,
          autoHideMenuBar: true,
          backgroundColor: "#1f1717",
          webPreferences: {
            preload: path.join(__dirname, "onr-login-preload.js"),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: false,
            partition: loginPartition
          }
        }
      }));
      webContents.on("did-create-window", (childWindow) => wireLoginWindow(childWindow));
      win.on("closed", () => {
        loginWindows.delete(win);
        if (!settled && win === loginWindow) {
          settled = true;
          if (timer) clearInterval(timer);
          reject(new Error("Login ONR cancelado."));
        }
      });
    };

    wireLoginWindow(loginWindow);
    timer = setInterval(checkToken, 1000);
    loadWebPkiExtensions(loginWindow.webContents.session)
      .then(() => loginWindow.loadURL(onrLoginUrl(config)))
      .catch((error) => finish(error));
  });
}

function loginToOnr(config, options = {}) {
  if (options.certificateThumbprint) {
    return loginToOnrWithCertificate(config, options.certificateThumbprint);
  }
  return loginToOnrWithWindow(config);
}

function parseExtraHeaders(config) {
  const text = String(config.onrExtraHeadersJson || "{}").trim() || "{}";
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (error) {
    throw new Error(`Os cabeçalhos extras da ONR não são um JSON válido: ${error.message}`);
  }
}

async function postJsonToOnr(config, endpoint, body) {
  const url = endpointUrl(config, endpoint);
  const portalUrl = normalizePortalUrl(config.onrPortalUrl);
  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "pt-br",
    "Origin": portalUrl,
    "Referer": `${portalUrl}/`,
    "X-Subscription": String(config.onrSubscription || ONR_DEFAULT_SUBSCRIPTION).trim() || ONR_DEFAULT_SUBSCRIPTION,
    ...parseExtraHeaders(config)
  };
  if (config.onrApiKey) headers["X-Api-Key"] = config.onrApiKey;
  if (config.onrBearerToken) headers.Authorization = `Bearer ${config.onrBearerToken}`;
  if (config.onrCookieHeader) headers.Cookie = config.onrCookieHeader;

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body)
    });
  } catch (error) {
    const friendly = new Error("Não foi possível estabeler conexão com o Assinador ONR");
    friendly.cause = error;
    throw friendly;
  }

  const text = await response.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    // Keep text response.
  }
  if (!response.ok) {
    const message = typeof data === "object" ? JSON.stringify(data) : String(data);
    if (response.status === 401) {
      throw new Error(
        `ONR respondeu HTTP 401: sem autorizacao. O endpoint exige Authorization Bearer ou uma API Key ONR valida. Resposta: ${message || "{}"}`
      );
    }
    throw new Error(`ONR respondeu HTTP ${response.status}: ${message || response.statusText}`);
  }
  return data;
}

async function requestJsonFromRestPki(config, endpoint, options = {}) {
  const url = endpointUrl(config, endpoint);
  const headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "pt-BR",
    ...parseExtraHeaders(config)
  };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (config.onrApiKey) headers["X-Api-Key"] = config.onrApiKey;
  if (config.onrBearerToken) headers.Authorization = `Bearer ${config.onrBearerToken}`;

  let response;
  try {
    response = await fetch(url, {
      method: options.method || "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body)
    });
  } catch (error) {
    const friendly = new Error("Não foi possível estabelecer conexão com o Assinador ONR");
    friendly.cause = error;
    throw friendly;
  }

  const text = await response.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    // Keep text response.
  }
  if (!response.ok) {
    const message = typeof data === "object" ? JSON.stringify(data) : String(data);
    if (response.status === 401) {
      throw new Error(
        `ONR respondeu HTTP 401: sem autorizacao. Configure uma API Key valida em X-Api-Key. Resposta: ${message || "{}"}`
      );
    }
    throw new Error(`ONR respondeu HTTP ${response.status}: ${message || response.statusText}`);
  }
  return data;
}

function valueFromAnyCase(source, keys) {
  if (!source || typeof source !== "object") return "";
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null) return source[key];
  }
  return "";
}

function extractRestPkiRedirectUrl(response) {
  return String(valueFromAnyCase(response, ["redirectUrl", "RedirectUrl", "url", "Url"]) || "").trim();
}

function extractRestPkiSessionId(response) {
  return String(valueFromAnyCase(response, ["signatureSessionId", "SignatureSessionId", "sessionId", "id", "Id"]) || "").trim();
}

function restPkiSessionStatus(session) {
  return String(valueFromAnyCase(session, ["status", "Status"]) || "").trim();
}

function firstRestPkiSignedFile(session) {
  const documents = valueFromAnyCase(session, ["documents", "Documents"]);
  if (!Array.isArray(documents)) return null;
  for (const document of documents) {
    const signedFile = valueFromAnyCase(document, ["signedFile", "SignedFile"]);
    if (!signedFile || typeof signedFile !== "object") continue;
    const location = valueFromAnyCase(signedFile, ["location", "Location", "url", "Url", "downloadUrl", "DownloadUrl"]);
    if (location) return signedFile;
  }
  return null;
}

async function waitForRestPkiSession(config, signatureSessionId) {
  let lastSession = null;
  for (let attempt = 0; attempt < 15; attempt += 1) {
    const session = await requestJsonFromRestPki(config, `/api/signature-sessions/${encodeURIComponent(signatureSessionId)}`);
    lastSession = session;
    const status = restPkiSessionStatus(session).toLowerCase();
    if (status === "completed") return session;
    if (status === "usercancelled" || status === "user_cancelled" || status === "cancelled" || status === "canceled") {
      throw new Error("Assinatura ONR cancelada pelo usuario.");
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return lastSession;
}

async function downloadRestPkiSignedFile(config, signedFile) {
  const location = String(valueFromAnyCase(signedFile, ["location", "Location", "url", "Url", "downloadUrl", "DownloadUrl"]) || "").trim();
  if (!location) throw new Error("A ONR não retornou o link do PDF assinado.");

  const headers = {
    "Accept": "application/pdf, application/octet-stream, */*"
  };
  if (config.onrApiKey) headers["X-Api-Key"] = config.onrApiKey;

  const response = await fetch(location, { headers });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`ONR respondeu HTTP ${response.status} ao baixar o PDF assinado: ${text || response.statusText}`);
  }
  return Buffer.from(await response.arrayBuffer()).toString("base64");
}

function workflowAbortError() {
  const error = new Error("Operação cancelada pelo usuário.");
  error.name = "AbortError";
  error.code = "user_cancelled";
  return error;
}

function beginWorkflowOperation(operationId, kind) {
  const id = String(operationId || "").trim();
  if (!id) throw new Error("Identificador da operação não informado.");
  if (workflowOperations.has(id)) throw new Error("Esta operação já está em andamento.");
  const operation = {
    id,
    kind,
    controller: new AbortController(),
    child: null
  };
  workflowOperations.set(id, operation);
  return operation;
}

function throwIfWorkflowCancelled(operation) {
  if (operation?.controller.signal.aborted) throw workflowAbortError();
}

function terminateChildTree(child) {
  if (!child || !child.pid) return;
  if (process.platform !== "win32") {
    child.kill("SIGTERM");
    return;
  }
  const killer = childProcess.spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
    windowsHide: true,
    stdio: "ignore"
  });
  killer.on("error", () => {
    try {
      child.kill();
    } catch {}
  });
}

function cancelWorkflowOperation(operationId) {
  const operation = workflowOperations.get(String(operationId || "").trim());
  if (!operation) return false;
  operation.controller.abort();
  terminateChildTree(operation.child);
  return true;
}

function finishWorkflowOperation(operation) {
  if (!operation) return;
  operation.child = null;
  workflowOperations.delete(operation.id);
}

function runPdfWorker(operation, task, payload, onProgress) {
  throwIfWorkflowCancelled(operation);
  const workerPath = path.join(__dirname, "core", "pdf-worker.js");
  const child = childProcess.fork(workerPath, [], {
    env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    windowsHide: true
  });
  operation.child = child;

  return new Promise((resolve, reject) => {
    let settled = false;
    const signal = operation.controller.signal;

    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      child.removeAllListeners();
      if (operation.child === child) operation.child = null;
      if (error) reject(error);
      else resolve(result);
    };

    const onAbort = () => {
      terminateChildTree(child);
      finish(workflowAbortError());
    };

    signal.addEventListener("abort", onAbort, { once: true });
    child.on("message", (message = {}) => {
      if (message.type === "progress") {
        onProgress?.(message.message, message.percent);
        return;
      }
      if (message.type === "result") {
        finish(null, message.result);
        return;
      }
      if (message.type === "error") {
        const error = new Error(message.error?.message || "Falha ao processar o PDF.");
        if (message.error?.stack) error.stack = message.error.stack;
        finish(error);
      }
    });
    child.on("error", (error) => finish(error));
    child.on("exit", (code) => {
      if (signal.aborted) finish(workflowAbortError());
      else if (!settled) finish(new Error(`O processamento do PDF foi encerrado inesperadamente (código ${code ?? "desconhecido"}).`));
    });
    child.send({ task, payload });
  });
}

function emitWorkflowProgress(sender, channel, message, percent = 0) {
  if (!sender || sender.isDestroyed()) return;
  sender.send(channel, {
    message,
    percent: Math.max(0, Math.min(100, Number(percent) || 0))
  });
}

function pdfProgressPercent(message, stage = "convert") {
  const text = String(message || "").toLowerCase();
  if (stage === "onr") {
    if (text.includes("criado:")) return 18;
    if (text.includes("convertendo para pdf/a")) return 12;
    if (text.includes("preparando arquivo")) return 8;
    if (text.includes("verificando pdf/a")) return 5;
    return 7;
  }
  if (text.includes("criado:")) return stage === "convert" ? 96 : 55;
  if (text.includes("convertendo para pdf/a")) return stage === "convert" ? 42 : 30;
  if (text.includes("preparando arquivo")) return stage === "convert" ? 18 : 22;
  if (text.includes("verificando pdf/a")) return 12;
  return stage === "convert" ? 10 : 18;
}

function emitOnrProgress(message, percent = 0) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send("onr:progress", {
    message,
    percent: Math.max(0, Math.min(100, Number(percent) || 0))
  });
}

function throwIfOnrCancelled(signal) {
  if (!signal?.aborted) return;
  const error = new Error("Assinatura ONR cancelada pelo usuário.");
  error.name = "AbortError";
  throw error;
}

async function runOnrDocumentSignature(payload = {}, options = {}) {
  const config = mergeConfigFromPayload(payload.config || {});
  const signal = options.signal;
  if (!String(config.onrApiKey || "").trim()) {
    throw new Error("Configure a API Key (X-Api-Key) da ONR nas Configurações antes de assinar.");
  }
  if (!payload.contentBase64) throw new Error("Documento não informado para assinatura ONR.");
  const certificateThumbprint = String(payload.certificateThumbprint || "").trim();
  if (!certificateThumbprint) throw new Error("Selecione um certificado digital válido para assinatura.");
  throwIfOnrCancelled(signal);

  emitOnrProgress("Lendo o certificado A3 selecionado...", 20);
  const certificateResult = await runWebPkiWithAutoLicense(config, (resolvedConfig) => {
    return webPkiNative.readCertificate(resolvedConfig, certificateThumbprint, { signal });
  });
  throwIfOnrCancelled(signal);
  const certificateContent = certificateContentFromWebPki(certificateResult);
  if (!certificateContent) throw new Error("O Web PKI não retornou o certificado selecionado.");

  emitOnrProgress("Enviando o documento para preparação no Assinador ONR...", 35);
  const prepared = await onrApi.prepareSignature(config, {
    contentBase64: payload.contentBase64,
    fileName: payload.fileName || "documento.pdf",
    certificateContent
  }, { signal });
  throwIfOnrCancelled(signal);
  const signatureParameters = onrApi.signatureHashParameters(prepared);

  emitOnrProgress("Documento preparado. Autorize o uso do certificado e digite o PIN do token.", 58);
  const pinReminder = setTimeout(() => {
    emitOnrProgress("Aguardando o PIN do certificado A3. Verifique também a barra de tarefas do Windows.", 62);
  }, 5000);
  const tokenReminder = setTimeout(() => {
    emitOnrProgress("O token ainda não respondeu. Confirme se ele está conectado e se a janela de PIN está aberta.", 65);
  }, 30000);
  let nativeSignature;
  try {
    nativeSignature = await runWebPkiWithAutoLicense(config, (resolvedConfig) => {
      return webPkiNative.signHash(resolvedConfig, {
        thumbprint: certificateThumbprint,
        hash: signatureParameters.hash,
        digestAlgorithm: signatureParameters.digestAlgorithm,
        signal
      });
    });
  } finally {
    clearTimeout(pinReminder);
    clearTimeout(tokenReminder);
  }
  throwIfOnrCancelled(signal);
  const signature = webPkiStringResult(nativeSignature, ["signature", "value", "signedData", "content"]);
  if (!signature) throw new Error("O componente Web PKI não retornou a assinatura digital.");

  emitOnrProgress("Assinatura A3 recebida. Finalizando o documento na ONR...", 76);
  const document = await onrApi.completeSignature(config, {
    state: signatureParameters.state,
    signature
  }, { signal });
  throwIfOnrCancelled(signal);
  const signedFile = onrApi.signedFileFromDocument(document);
  if (!signedFile) throw new Error("A ONR não retornou o PDF assinado.");

  emitOnrProgress("Baixando o PDF assinado da ONR...", 90);
  const signedBase64 = await onrApi.downloadSignedFile(config, signedFile, { signal });
  throwIfOnrCancelled(signal);
  emitOnrProgress("PDF assinado recebido. Disponível para download.", 96);

  const documentKey = String(document?.key || document?.Key || "").trim();
  const formattedDocumentKey = String(document?.formattedKey || document?.FormattedKey || documentKey).trim();
  return {
    documentId: String(document?.id || document?.Id || "").trim(),
    documentKey,
    formattedDocumentKey,
    validationUrl: onrApi.documentValidationUrl(documentKey),
    status: "Completed",
    signedFileName: String(signedFile?.name || signedFile?.Name || "").trim(),
    signedBase64
  };
}

function safeFileNamePart(value, fallback = "documento") {
  const normalized = String(value || "")
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/[. ]+$/g, "")
    .trim();
  return normalized || fallback;
}

function uniquePdfPath(directory, baseName) {
  const first = path.join(directory, `${baseName}.pdf`);
  if (!fs.existsSync(first)) return first;
  for (let index = 2; index < 10000; index += 1) {
    const candidate = path.join(directory, `${baseName} (${index}).pdf`);
    if (!fs.existsSync(candidate)) return candidate;
  }
  throw new Error("Não foi possível escolher um nome livre para o PDF assinado.");
}

function extractSignedPdfBase64(result) {
  const direct = [
    result?.signatureInfo?.content,
    result?.content,
    result?.signedContent,
    result?.signatureContent,
    result?.pdfContent,
    result?.output?.content
  ].filter((value) => typeof value === "string");
  for (const value of direct) {
    if (value.length > 100 && value.slice(0, 8).includes("JVBER")) return value;
  }

  const seen = new Set();
  const queue = [result];
  while (queue.length) {
    const item = queue.shift();
    if (!item || typeof item !== "object" || seen.has(item)) continue;
    seen.add(item);
    for (const value of Object.values(item)) {
      if (typeof value === "string" && value.length > 100 && value.slice(0, 12).includes("JVBER")) return value;
      if (value && typeof value === "object") queue.push(value);
    }
  }
  return "";
}

async function prepareSignatureInWorker(operation, payload, sender, channel, stage = "signature") {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `pdfutils_${stage}_`));
  try {
    const prepared = await runPdfWorker(
      operation,
      "prepare-signature",
      { ...payload, tempDir },
      (message) => emitWorkflowProgress(sender, channel, message, pdfProgressPercent(message, stage))
    );
    throwIfWorkflowCancelled(operation);
    return {
      ...prepared,
      tempDir,
      pdfBase64: pdf.readPdfBase64(prepared.preparedPath)
    };
  } catch (error) {
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

async function runLocalPdfSignature(operation, payload, sender) {
  const sourcePath = String(payload.sourcePath || "").trim();
  const outputPath = String(payload.outputPath || "").trim();
  const certificateThumbprint = String(payload.certificateThumbprint || "").trim();
  if (!sourcePath) throw new Error("Selecione um arquivo válido para assinar.");
  if (!outputPath) throw new Error("Escolha o arquivo de saída para o PDF assinado.");
  if (!certificateThumbprint) throw new Error("Selecione um certificado digital válido para assinatura.");

  let prepared = null;
  try {
    emitWorkflowProgress(sender, "signature:progress", "Verificando e preparando o documento em PDF/A...", 7);
    prepared = await prepareSignatureInWorker(operation, {
      sourcePath,
      outputBaseName: payload.outputBaseName || path.basename(outputPath, path.extname(outputPath))
    }, sender, "signature:progress", "signature");
    throwIfWorkflowCancelled(operation);

    emitWorkflowProgress(
      sender,
      "signature:progress",
      prepared.converted ? "Documento convertido para PDF/A." : "Documento já estava em PDF/A.",
      58
    );
    emitWorkflowProgress(sender, "signature:progress", "Autorize o certificado A3 e digite o PIN do token.", 68);
    const config = mergeConfigFromPayload(payload.config || {});
    const signResult = await runWebPkiWithAutoLicense(config, (resolvedConfig) => {
      return webPkiNative.signPdf(resolvedConfig, {
        pdfBase64: prepared.pdfBase64,
        certificateThumbprint,
        signal: operation.controller.signal
      });
    });
    throwIfWorkflowCancelled(operation);
    if (signResult?.isValid === false) throw new Error("O Web PKI retornou uma assinatura inválida.");
    const signedBase64 = extractSignedPdfBase64(signResult);
    if (!signedBase64) throw new Error("O Web PKI não retornou o PDF assinado.");

    emitWorkflowProgress(sender, "signature:progress", "Salvando o PDF assinado...", 94);
    const output = pdf.writePdfBase64(outputPath, signedBase64);
    emitWorkflowProgress(sender, "signature:progress", "PDF assinado com sucesso.", 100);
    return { output, converted: prepared.converted };
  } finally {
    if (prepared?.tempDir) fs.rmSync(prepared.tempDir, { recursive: true, force: true });
  }
}

function onrFilePayload({ config, uploadResult, fileName, title, contentBase64 }) {
  const contentType = "application/pdf";
  if (uploadResult && uploadResult.id) {
    return {
      id: uploadResult.id,
      name: fileName,
      displayName: title || fileName,
      contentType
    };
  }
  return {
    name: fileName,
    displayName: title || fileName,
    contentType,
    bytes: contentBase64,
    content: contentBase64
  };
}

app.whenReady().then(async () => {
  await createWindow();
  setupAutoUpdater();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  for (const operation of workflowOperations.values()) {
    operation.controller.abort();
    terminateChildTree(operation.child);
  }
  workflowOperations.clear();
  for (const job of signatureJobs.values()) job.cleanup?.();
  signatureJobs.clear();
  for (const [state, callback] of restPkiCallbacks.entries()) {
    clearTimeout(callback.timeout);
    restPkiCallbacks.delete(state);
  }
  server?.close();
});

ipcMain.handle("app:version", () => APP_VERSION);
ipcMain.handle("app:server-url", () => serverUrl);
ipcMain.handle("config:load", () => loadConfig());
ipcMain.handle("config:save", (_event, config) => saveConfig(config));
ipcMain.handle("onr-history:load", () => loadOnrHistory());
ipcMain.handle("onr-history:save", (_event, items) => saveOnrHistory(items));
ipcMain.handle("onr-history:add", (_event, item) => addOnrHistoryItem(item));
ipcMain.handle("onr:login", (_event, payload = {}) => {
  const config = { ...loadConfig(), ...(payload.config || {}) };
  return loginToOnr(config, { certificateThumbprint: payload.certificateThumbprint });
});
ipcMain.handle("onr:signature-session", async (_event, payload = {}) => {
  const operation = beginWorkflowOperation(payload.operationId, "sign-onr");
  let prepared = null;
  try {
    let signaturePayload = payload;
    if (String(payload.sourcePath || "").trim()) {
      emitWorkflowProgress(_event.sender, "onr:progress", "Preparando o documento em PDF/A...", 3);
      prepared = await prepareSignatureInWorker(operation, {
        sourcePath: payload.sourcePath,
        outputBaseName: payload.title || path.basename(payload.sourcePath, path.extname(payload.sourcePath))
      }, _event.sender, "onr:progress", "onr");
      signaturePayload = {
        ...payload,
        contentBase64: prepared.pdfBase64,
        fileName: payload.fileName || `${payload.title || path.basename(payload.sourcePath, path.extname(payload.sourcePath))}.pdf`
      };
      emitWorkflowProgress(
        _event.sender,
        "onr:progress",
        prepared.converted ? "Documento convertido para PDF/A." : "Documento já estava em PDF/A.",
        19
      );
    }
    const result = await runOnrDocumentSignature(signaturePayload, { signal: operation.controller.signal });

    addOnrHistoryItem({
    fileName: payload.title || path.basename(signaturePayload.fileName || payload.sourcePath || "documento.pdf", ".pdf"),
    endpointLink: result.validationUrl || onrApi.documentValidationUrl(result.documentKey),
    signedAt: new Date().toISOString()
    });
    
    return { ...result, converted: Boolean(prepared?.converted) };
  } catch (error) {
    if (operation.controller.signal.aborted || error?.name === "AbortError") {
      throw new Error("Assinatura ONR cancelada pelo usuário.");
    }
    throw error;
  } finally {
    if (prepared?.tempDir) fs.rmSync(prepared.tempDir, { recursive: true, force: true });
    finishWorkflowOperation(operation);
  }
});
ipcMain.handle("onr:cancel-signature", (_event, operationId) => {
  return cancelWorkflowOperation(operationId);
});
ipcMain.handle("workflow:cancel", (_event, operationId) => cancelWorkflowOperation(operationId));
ipcMain.handle("certificates:list", () => webPkiNative.listCertificates(loadConfig()));
ipcMain.handle("webpki:diagnostics", () => webPkiNative.diagnostics());
ipcMain.handle("webpki:read-certificate", async (_event, payload = {}) => {
  const config = mergeConfigFromPayload(payload.config || {});
  return runWebPkiWithAutoLicense(config, (resolvedConfig) => {
    const requestConfig = payload.webPkiDomain ? { ...resolvedConfig, webPkiDomain: payload.webPkiDomain } : resolvedConfig;
    return webPkiNative.readCertificate(requestConfig, payload.thumbprint);
  });
});
ipcMain.handle("webpki:sign-hash", async (_event, payload = {}) => {
  const config = mergeConfigFromPayload(payload.config || {});
  return runWebPkiWithAutoLicense(config, (resolvedConfig) => webPkiNative.signHash(resolvedConfig, payload));
});
ipcMain.handle("webpki:sign-data", async (_event, payload = {}) => {
  const config = mergeConfigFromPayload(payload.config || {});
  return runWebPkiWithAutoLicense(config, (resolvedConfig) => {
    const requestConfig = payload.webPkiDomain ? { ...resolvedConfig, webPkiDomain: payload.webPkiDomain } : resolvedConfig;
    return webPkiNative.signData(requestConfig, payload);
  });
});
ipcMain.handle("webpki:sign-pdf", async (_event, payload = {}) => {
  const config = mergeConfigFromPayload(payload.config || {});
  return runWebPkiWithAutoLicense(config, (resolvedConfig) => webPkiNative.signPdf(resolvedConfig, payload));
});

ipcMain.handle("dialog:open-file", async (_event, options = {}) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: options.title || "Escolher arquivo",
    properties: ["openFile"],
    filters: options.filters || [{ name: "Arquivos", extensions: ["pdf", "doc", "docx", "odt", "png", "jpg", "jpeg", "tif", "tiff"] }]
  });
  return result.canceled ? "" : result.filePaths[0];
});

ipcMain.handle("dialog:open-files", async (_event, options = {}) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: options.title || "Escolher arquivos",
    properties: ["openFile", "multiSelections"],
    filters: options.filters || [{ name: "Arquivos", extensions: ["pdf", "doc", "docx", "odt", "rtf", "xls", "xlsx", "ods", "ppt", "pptx", "odp", "txt", "csv", "png", "jpg", "jpeg", "bmp", "tif", "tiff"] }]
  });
  return result.canceled ? [] : result.filePaths;
});

ipcMain.handle("dialog:save-pdf", async (_event, options = {}) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    title: options.title || "Salvar PDF",
    defaultPath: options.defaultPath || "documento.pdf",
    filters: [{ name: "PDF", extensions: ["pdf"] }]
  });
  return result.canceled ? "" : pdf.ensurePdfExtension(result.filePath);
});

ipcMain.handle("dialog:open-directory", async (_event, options = {}) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: options.title || "Escolher pasta",
    defaultPath: options.defaultPath || undefined,
    properties: ["openDirectory", "createDirectory"]
  });
  return result.canceled ? "" : result.filePaths[0];
});

ipcMain.handle("shell:open-path", (_event, target) => shell.openPath(target));
ipcMain.handle("shell:show-item-in-folder", (_event, target) => {
  shell.showItemInFolder(target);
  return true;
});
ipcMain.handle("shell:open-external", (_event, target) => shell.openExternal(target));
ipcMain.handle("dependencies:ghostscript-status", () => ghostscriptStatus());
ipcMain.handle("dependencies:install-ghostscript", (event, payload = {}) => installGhostscript(event.sender, payload));
ipcMain.handle("logs:write", (_event, payload) => {
  const error = new Error(payload?.message || "Erro não identificado");
  if (payload?.stack) error.stack = payload.stack;
  return saveErrorLog(error, payload?.context || {});
});

ipcMain.handle("pdfa:convert", async (event, payload = {}) => {
  const operation = beginWorkflowOperation(payload.operationId, "convert");
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pdfutils_convert_"));
  const requestedOutput = String(payload.outputPath || "").trim();
  const outputPath = requestedOutput ? path.resolve(pdf.ensurePdfExtension(requestedOutput)) : "";
  const temporaryOutput = path.join(workDir, "resultado.pdf");
  try {
    if (!outputPath) throw new Error("Escolha o nome do PDF/A de saída.");
    emitWorkflowProgress(event.sender, "pdfa:progress", "Iniciando conversão para PDF/A...", 3);
    const result = await runPdfWorker(
      operation,
      "convert",
      {
        ...payload,
        outputPath: temporaryOutput,
        tempDir: path.join(workDir, "work")
      },
      (message) => emitWorkflowProgress(event.sender, "pdfa:progress", message, pdfProgressPercent(message, "convert"))
    );
    throwIfWorkflowCancelled(operation);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.copyFileSync(temporaryOutput, outputPath);
    emitWorkflowProgress(event.sender, "pdfa:progress", "PDF/A criado com sucesso.", 100);
    return { ...result, output: outputPath, pdfaLog: "" };
  } catch (error) {
    if (operation.controller.signal.aborted || error?.name === "AbortError") {
      throw new Error("Conversão para PDF/A cancelada pelo usuário.");
    }
    throw error;
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
    finishWorkflowOperation(operation);
  }
});

ipcMain.handle("pdfa:validate", (_event, payload) => pdf.validatePdfA(payload));
ipcMain.handle("signature:validate", (_event, payload) => signatureValidation.validatePdfSignatures(payload));

ipcMain.handle("pdf:merge", async (event, payload = {}) => {
  const operation = beginWorkflowOperation(payload.operationId, "merge");
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pdfutils_merge_"));
  const sourcePaths = Array.isArray(payload.sourcePaths)
    ? payload.sourcePaths.map((source) => path.resolve(String(source || "").trim())).filter(Boolean)
    : [];
  const requestedOutput = String(payload.outputPath || "").trim();
  const outputPath = requestedOutput ? path.resolve(pdf.ensurePdfExtension(requestedOutput)) : "";
  const temporaryOutput = path.join(workDir, "resultado.pdf");
  try {
    if (sourcePaths.length < 2) throw new Error("Adicione pelo menos dois arquivos para juntar.");
    if (!outputPath) throw new Error("Escolha o nome do PDF final.");
    if (sourcePaths.some((source) => path.normalize(source).toLowerCase() === path.normalize(outputPath).toLowerCase())) {
      throw new Error("O PDF final deve ter um nome diferente dos arquivos de origem.");
    }
    emitWorkflowProgress(event.sender, "pdf:merge-progress", "Iniciando a junção dos arquivos...", 2);
    const result = await runPdfWorker(
      operation,
      "merge",
      {
        sourcePaths,
        outputPath: temporaryOutput,
        tempDir: path.join(workDir, "work")
      },
      (message, percent) => emitWorkflowProgress(event.sender, "pdf:merge-progress", message, percent)
    );
    throwIfWorkflowCancelled(operation);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.copyFileSync(temporaryOutput, outputPath);
    emitWorkflowProgress(event.sender, "pdf:merge-progress", "PDF final criado com sucesso.", 100);
    return { ...result, output: outputPath };
  } catch (error) {
    if (operation.controller.signal.aborted || error?.name === "AbortError") {
      throw new Error("Junção de arquivos cancelada pelo usuário.");
    }
    throw error;
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
    finishWorkflowOperation(operation);
  }
});

ipcMain.handle("signature:prepare-pdf", async (event, payload) => {
  const prepared = await pdf.preparePdfAForSigning(payload, (message) => event.sender.send("signature:progress", message));
  const jobId = cryptoRandomId();
  signatureJobs.set(jobId, prepared);
  return {
    jobId,
    preparedPath: prepared.preparedPath,
    pdfBase64: pdf.readPdfBase64(prepared.preparedPath),
    converted: prepared.converted,
    conversion: prepared.conversion || null,
    validation: prepared.validation || null
  };
});

ipcMain.handle("signature:sign-session", async (event, payload = {}) => {
  const operation = beginWorkflowOperation(payload.operationId, "sign-pdf");
  try {
    return await runLocalPdfSignature(operation, payload, event.sender);
  } catch (error) {
    if (operation.controller.signal.aborted || error?.name === "AbortError") {
      throw new Error("Assinatura do PDF cancelada pelo usuário.");
    }
    throw error;
  } finally {
    finishWorkflowOperation(operation);
  }
});

ipcMain.handle("signature:save-signed", (_event, payload) => {
  const output = pdf.writePdfBase64(payload.outputPath, payload.signedBase64);
  const job = signatureJobs.get(payload.jobId);
  job?.cleanup?.();
  signatureJobs.delete(payload.jobId);
  return { output };
});

ipcMain.handle("signature:save-signed-auto", (_event, payload = {}) => {
  const sourcePath = String(payload.sourcePath || "").trim();
  if (!sourcePath) throw new Error("Arquivo original não informado para salvar o PDF assinado.");
  const configuredFolder = String(payload.outputFolder || "").trim();
  const outputDirectory = path.resolve(configuredFolder || path.dirname(sourcePath));
  fs.mkdirSync(outputDirectory, { recursive: true });
  const originalName = path.basename(sourcePath, path.extname(sourcePath));
  const outputName = `${safeFileNamePart(payload.outputBaseName || originalName)} - ONR assinado`;
  const outputPath = uniquePdfPath(outputDirectory, outputName);
  const output = pdf.writePdfBase64(outputPath, payload.signedBase64);
  const job = signatureJobs.get(payload.jobId);
  job?.cleanup?.();
  signatureJobs.delete(payload.jobId);
  return { output };
});

ipcMain.handle("signature:cleanup", (_event, jobId) => {
  const job = signatureJobs.get(jobId);
  job?.cleanup?.();
  signatureJobs.delete(jobId);
  return true;
});

ipcMain.handle("onr:start", async (_event, payload) => {
  const config = mergeConfigFromPayload(payload.config || {});
  let uploadResult = null;
  if (config.onrUseUploadBytes) {
    uploadResult = await postJsonToOnr(config, config.onrUploadBytesEndpoint, { bytes: payload.contentBase64 });
  }
  const file = onrFilePayload({
    config,
    uploadResult,
    fileName: payload.fileName || "documento.pdf",
    title: payload.title || payload.fileName || "documento.pdf",
    contentBase64: payload.contentBase64
  });
  const body = {
    file,
    certificate: payload.certificateContent,
    isAuthentication: false,
    attributeCertificateId: null,
    userTimeZoneOffset: -new Date().getTimezoneOffset(),
    title: payload.title || null,
    organizationId: config.onrOrganizationId || null,
    folderId: config.onrFolderId || null,
    newFolderName: config.onrNewFolderName || null
  };
  const result = await postJsonToOnr(config, config.onrStartEndpoint, body);
  if (result && result.success === false) throw new Error("A ONR recusou a preparacao da assinatura.");
  return { ...result, file };
});

ipcMain.handle("onr:complete", async (_event, payload) => {
  const config = mergeConfigFromPayload(payload.config || {});
  const body = {
    file: payload.file,
    signature: payload.signature,
    token: payload.token,
    organizationId: config.onrOrganizationId || null,
    folderId: config.onrFolderId || null,
    newFolderName: config.onrNewFolderName || null,
    notifiedEmails: [],
    title: payload.title || null
  };
  const result = await postJsonToOnr(config, config.onrCompleteEndpoint, body);
  if (result && result.success === false) throw new Error("A ONR não conseguiu finalizar o documento.");
  return result;
});

ipcMain.handle("update:check", async () => {
  if (!app.isPackaged || isSmokeTest) return lastUpdateState;
  updateDownloaded = false;
  await autoUpdater.checkForUpdates();
  return lastUpdateState;
});

ipcMain.handle("update:install", () => {
  if (!updateDownloaded) return false;
  publishUpdateState({ status: "installing", percent: 100, message: "Instalando atualizacao e reiniciando..." });
  autoUpdater.quitAndInstall(false, true);
  return true;
});

function cryptoRandomId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
}
