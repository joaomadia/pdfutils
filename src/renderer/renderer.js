const api = window.pdfUtils;

const knownMessages = [
  "Não foi possível estabelecer conexão com o Assinador ONR",
  "Não foram encontrados certificados digitais válidos para assinatura",
  "Componente Web PKI não encontrado, por favor faça a instalação na aba de configurações e tente novamente.",
  "Ghostscript não encontrado",
  "Licença Web PKI ausente ou inválida",
  "ONR respondeu HTTP 401",
  "Configure a API Key",
  "Assinatura ONR cancelada",
  "Conversão para PDF/A cancelada",
  "Assinatura do PDF cancelada",
  "Junção de arquivos cancelada",
  "Adicione pelo menos dois arquivos",
  "Escolha o nome do PDF final",
  "Operação cancelada",
  "Tempo esgotado aguardando retorno da assinatura ONR",
  "Tempo esgotado aguardando a assinatura no portal ONR",
  "API Key não possui permissão",
  "Assinatura ONR recusada",
  "Assinatura ONR cancelada",
  "Assinatura ONR expirada",
  "Não foi possível carregar o login ONR",
  "Login ONR não retornou",
  "Login ONR não ofereceu",
  "Selecione um certificado digital"
];

let config = {};
let certificates = [];
let activeConvertOperationId = "";
let convertCancelRequested = false;
let mergeFiles = [];
let mergeOutputCustomized = false;
const mergeState = {
  running: false,
  finished: false,
  cancelRequested: false,
  operationId: "",
  generation: 0
};
let activeSignOperationId = "";
let signCancelRequested = false;
let activeOnrOperationId = "";
let onrCancelRequested = false;
let completedOnrSignature = null;
let onrHistoryItems = [];
let onrHistoryCurrentPage = 1;
const themeStorageKey = "pdfutils-theme";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const els = {
  version: $("#version"),
  updateStatus: $("#updateStatus"),
  checkUpdates: $("#checkUpdates"),
  installUpdate: $("#installUpdate"),
  themeToggle: $("#themeToggle"),
  globalStatus: $("#globalStatus"),

  convertSource: $("#convertSource"),
  convertOutput: $("#convertOutput"),
  convertResult: $("#convertResult"),
  pickConvertSource: $("#pickConvertSource"),
  pickConvertOutput: $("#pickConvertOutput"),
  convertButton: $("#convertButton"),
  openConvertOutput: $("#openConvertOutput"),
  convertProgress: $("#convertProgress"),
  convertProgressLabel: $("#convertProgressLabel"),
  convertProgressValue: $("#convertProgressValue"),
  convertProgressTrack: $("#convertProgressTrack"),
  convertProgressBar: $("#convertProgressBar"),
  cancelConvertButton: $("#cancelConvertButton"),

  mergeFileCount: $("#mergeFileCount"),
  mergeDropZone: $("#mergeDropZone"),
  mergeEmptyState: $("#mergeEmptyState"),
  mergeFileList: $("#mergeFileList"),
  mergeOutput: $("#mergeOutput"),
  mergeResult: $("#mergeResult"),
  addMergeFiles: $("#addMergeFiles"),
  pickMergeOutput: $("#pickMergeOutput"),
  mergeButton: $("#mergeButton"),
  openMergeOutput: $("#openMergeOutput"),
  mergeProgress: $("#mergeProgress"),
  mergeProgressLabel: $("#mergeProgressLabel"),
  mergeProgressValue: $("#mergeProgressValue"),
  mergeProgressTrack: $("#mergeProgressTrack"),
  mergeProgressBar: $("#mergeProgressBar"),
  cancelMergeButton: $("#cancelMergeButton"),

  validateSource: $("#validateSource"),
  validateResult: $("#validateResult"),
  validateBadge: $("#validateBadge"),
  pickValidateSource: $("#pickValidateSource"),
  validateButton: $("#validateButton"),

  signatureValidationSource: $("#signatureValidationSource"),
  signatureValidationResult: $("#signatureValidationResult"),
  pickSignatureValidationSource: $("#pickSignatureValidationSource"),
  validateSignaturesButton: $("#validateSignaturesButton"),

  signSource: $("#signSource"),
  signOutput: $("#signOutput"),
  signCertificate: $("#signCertificate"),
  signResult: $("#signResult"),
  pickSignSource: $("#pickSignSource"),
  pickSignOutput: $("#pickSignOutput"),
  refreshSignCertificates: $("#refreshSignCertificates"),
  signPdfButton: $("#signPdfButton"),
  openSignOutput: $("#openSignOutput"),
  signProgress: $("#signProgress"),
  signProgressLabel: $("#signProgressLabel"),
  signProgressValue: $("#signProgressValue"),
  signProgressTrack: $("#signProgressTrack"),
  signProgressBar: $("#signProgressBar"),
  cancelSignButton: $("#cancelSignButton"),

  onrSource: $("#onrSource"),
  onrTitle: $("#onrTitle"),
  onrCertificate: $("#onrCertificate"),
  onrResult: $("#onrResult"),
  pickOnrSource: $("#pickOnrSource"),
  refreshOnrCertificates: $("#refreshOnrCertificates"),
  signOnrButton: $("#signOnrButton"),
  onrProgress: $("#onrProgress"),
  onrProgressLabel: $("#onrProgressLabel"),
  onrProgressValue: $("#onrProgressValue"),
  onrProgressTrack: $("#onrProgressTrack"),
  onrProgressBar: $("#onrProgressBar"),
  cancelOnrButton: $("#cancelOnrButton"),
  onrCompleteActions: $("#onrCompleteActions"),
  downloadOnrButton: $("#downloadOnrButton"),
  openOnrValidationButton: $("#openOnrValidationButton"),

  ghostscriptStatus: $("#ghostscriptStatus"),
  installGhostscript: $("#installGhostscript"),
  checkGhostscript: $("#checkGhostscript"),
  webPkiInstallerUrl: $("#webPkiInstallerUrl"),
  webPkiLicense: $("#webPkiLicense"),
  onrBaseUrl: $("#onrBaseUrl"),
  onrPortalUrl: $("#onrPortalUrl"),
  onrStartEndpoint: $("#onrStartEndpoint"),
  onrCompleteEndpoint: $("#onrCompleteEndpoint"),
  onrUploadBytesEndpoint: $("#onrUploadBytesEndpoint"),
  onrUseUploadBytes: $("#onrUseUploadBytes"),
  onrSubscription: $("#onrSubscription"),
  onrApiKey: $("#onrApiKey"),
  onrOutputFolder: $("#onrOutputFolder"),
  onrBearerToken: $("#onrBearerToken"),
  onrExtraHeadersJson: $("#onrExtraHeadersJson"),
  loginOnr: $("#loginOnr"),
  clearOnrToken: $("#clearOnrToken"),
  pickOnrOutputFolder: $("#pickOnrOutputFolder"),
  clearOnrOutputFolder: $("#clearOnrOutputFolder"),
  openWebPkiInstaller: $("#openWebPkiInstaller"),
  saveSettings: $("#saveSettings"),
  settingsResult: $("#settingsResult")
};

const generalFileExtensions = ["pdf", "doc", "docx", "odt", "rtf", "png", "jpg", "jpeg", "bmp", "tif", "tiff"];
const mergeFileExtensions = [
  "pdf", "doc", "docx", "odt", "rtf",
  "xls", "xlsx", "ods", "csv",
  "ppt", "pptx", "odp",
  "txt", "png", "jpg", "jpeg", "bmp", "tif", "tiff"
];
const mergeFileFilters = [{ name: "Documentos e imagens", extensions: mergeFileExtensions }];
const fileFlows = {
  convert: {
    screen: "convert",
    source: els.convertSource,
    output: els.convertOutput,
    outputSuffix: " - PDF-A",
    pickButton: els.pickConvertSource,
    processButton: els.convertButton,
    result: els.convertResult,
    title: "Converter para PDF/A",
    extensions: generalFileExtensions,
    filters: [{ name: "Documentos", extensions: generalFileExtensions }],
    controlsDuringRun: [els.pickConvertOutput]
  },
  validate: {
    screen: "validate",
    source: els.validateSource,
    pickButton: els.pickValidateSource,
    processButton: els.validateButton,
    result: els.validateResult,
    title: "Validar PDF/A",
    extensions: ["pdf"],
    filters: [{ name: "PDF", extensions: ["pdf"] }]
  },
  "validate-signatures": {
    screen: "validate-signatures",
    source: els.signatureValidationSource,
    pickButton: els.pickSignatureValidationSource,
    processButton: els.validateSignaturesButton,
    result: els.signatureValidationResult,
    title: "Validar Assinaturas",
    extensions: ["pdf"],
    filters: [{ name: "PDF", extensions: ["pdf"] }]
  },
  "sign-pdf": {
    screen: "sign-pdf",
    source: els.signSource,
    output: els.signOutput,
    outputSuffix: " - assinado",
    pickButton: els.pickSignSource,
    processButton: els.signPdfButton,
    result: els.signResult,
    title: "Assinar PDF",
    extensions: generalFileExtensions,
    filters: [{ name: "Documentos", extensions: generalFileExtensions }],
    controlsDuringRun: [els.pickSignOutput, els.signCertificate, els.refreshSignCertificates]
  },
  "sign-onr": {
    screen: "sign-onr",
    source: els.onrSource,
    derivedTitle: els.onrTitle,
    pickButton: els.pickOnrSource,
    processButton: els.signOnrButton,
    result: els.onrResult,
    title: "Assinar ONR",
    extensions: generalFileExtensions,
    filters: [{ name: "Documentos", extensions: generalFileExtensions }],
    controlsDuringRun: [els.onrTitle, els.onrCertificate, els.refreshOnrCertificates]
  }
};
const fileFlowStates = Object.fromEntries(
  Object.keys(fileFlows).map((name) => [name, {
    selected: false,
    running: false,
    finished: false,
    cancelRequested: false,
    operationId: "",
    generation: 0
  }])
);
const progressFlows = {
  convert: {
    container: els.convertProgress,
    label: els.convertProgressLabel,
    value: els.convertProgressValue,
    track: els.convertProgressTrack,
    bar: els.convertProgressBar,
    cancelButton: els.cancelConvertButton
  },
  "sign-pdf": {
    container: els.signProgress,
    label: els.signProgressLabel,
    value: els.signProgressValue,
    track: els.signProgressTrack,
    bar: els.signProgressBar,
    cancelButton: els.cancelSignButton
  },
  "sign-onr": {
    container: els.onrProgress,
    label: els.onrProgressLabel,
    value: els.onrProgressValue,
    track: els.onrProgressTrack,
    bar: els.onrProgressBar,
    cancelButton: els.cancelOnrButton
  }
};

function setStatus(message) {
  els.globalStatus.textContent = message;
}

function setResult(element, message) {
  element.textContent = message || "";
}

function appendResult(element, message) {
  element.textContent = `${element.textContent ? `${element.textContent}\n` : ""}${message}`;
  element.scrollTop = element.scrollHeight;
}

function normalizeTheme(theme) {
  return theme === "dark" ? "dark" : "light";
}

function readTheme() {
  try {
    const savedTheme = localStorage.getItem(themeStorageKey);
    if (savedTheme) return normalizeTheme(savedTheme);
  } catch {}

  return normalizeTheme(document.documentElement.dataset.theme);
}

function applyTheme(theme) {
  const normalizedTheme = normalizeTheme(theme);
  document.documentElement.dataset.theme = normalizedTheme;

  if (!els.themeToggle) return;
  const targetTheme = normalizedTheme === "dark" ? "claro" : "escuro";
  const label = `Ativar tema ${targetTheme}`;
  els.themeToggle.setAttribute("aria-label", label);
  els.themeToggle.title = label;
}

function toggleTheme() {
  const nextTheme = readTheme() === "dark" ? "light" : "dark";
  try {
    localStorage.setItem(themeStorageKey, nextTheme);
  } catch {}
  applyTheme(nextTheme);
}

function cleanErrorMessage(error) {
  const raw = String(error?.message || error || "Erro não identificado");
  return raw
    .replace(/^Error invoking remote method '[^']+': Error: /, "")
    .replace(/^Error invoking remote method "[^"]+": Error: /, "")
    .trim();
}

function isKnownError(message) {
  return knownMessages.some((known) => message.includes(known));
}

async function reportError(element, error, context = {}) {
  const message = cleanErrorMessage(error);
  if (isKnownError(message)) {
    setResult(element, message);
    setStatus(message);
    return;
  }
  let logPath = "";
  try {
    logPath = await api.writeLog({
      message,
      stack: error?.stack || "",
      context
    });
  } catch (_) {
    // The visible error is still more useful than hiding a secondary log failure.
  }
  setResult(element, logPath ? `Erro não identificado.\n\n${message}\n\nLog gerado:\n${logPath}` : `Erro não identificado.\n\n${message}`);
  setStatus("Erro não identificado.");
}

async function runTask(button, resultElement, context, task) {
  button.disabled = true;
  setStatus("Processando...");
  try {
    const result = await task();
    setStatus("Pronto.");
    return result;
  } catch (error) {
    await reportError(resultElement, error, context);
    return null;
  } finally {
    button.disabled = false;
  }
}

function showScreen(name) {
  $$(".screen").forEach((screen) => screen.classList.remove("active"));
  $(`#screen-${name}`).classList.add("active");
  setStatus("Pronto.");
}

function dirname(filePath) {
  const index = Math.max(filePath.lastIndexOf("\\"), filePath.lastIndexOf("/"));
  return index >= 0 ? filePath.slice(0, index) : "";
}

function basename(filePath) {
  const index = Math.max(filePath.lastIndexOf("\\"), filePath.lastIndexOf("/"));
  return index >= 0 ? filePath.slice(index + 1) : filePath;
}

function withoutExt(fileName) {
  const index = fileName.lastIndexOf(".");
  return index > 0 ? fileName.slice(0, index) : fileName;
}

function defaultOutputPath(sourcePath, suffix) {
  if (!sourcePath) return "";
  const folder = dirname(sourcePath);
  const name = withoutExt(basename(sourcePath));
  return `${folder ? `${folder}\\` : ""}${name}${suffix}.pdf`;
}

function fileExtension(filePath) {
  const name = basename(String(filePath || ""));
  const index = name.lastIndexOf(".");
  return index >= 0 ? name.slice(index + 1).toLowerCase() : "";
}

function mergeCountLabel(count) {
  if (!count) return "Nenhum arquivo";
  return `${count} ${count === 1 ? "arquivo" : "arquivos"}`;
}

function defaultMergeOutputPath() {
  return mergeFiles.length ? defaultOutputPath(mergeFiles[0], " - arquivos unidos") : "";
}

function syncMergeOutput() {
  if (!mergeFiles.length) {
    els.mergeOutput.value = "";
    mergeOutputCustomized = false;
  } else if (!mergeOutputCustomized) {
    els.mergeOutput.value = defaultMergeOutputPath();
  }
}

function resetMergeProgress() {
  els.mergeProgress.hidden = true;
  els.mergeProgressLabel.textContent = "";
  els.mergeProgressValue.textContent = "0%";
  els.mergeProgressBar.style.width = "0%";
  els.mergeProgressTrack.setAttribute("aria-valuenow", "0");
  els.cancelMergeButton.hidden = false;
  els.cancelMergeButton.disabled = false;
}

function setMergeProgress(percent, message, options = {}) {
  if (!mergeState.running && !options.force) return;
  const value = Math.max(0, Math.min(100, Math.round(Number(percent) || 0)));
  els.mergeProgress.hidden = false;
  els.mergeProgressLabel.textContent = message || "Processando arquivos...";
  els.mergeProgressValue.textContent = `${value}%`;
  els.mergeProgressBar.style.width = `${value}%`;
  els.mergeProgressTrack.setAttribute("aria-valuenow", String(value));
  if (value >= 100) els.cancelMergeButton.hidden = true;
}

function updateMergeControls() {
  const locked = mergeState.running;
  els.addMergeFiles.disabled = locked;
  els.pickMergeOutput.disabled = locked || !mergeFiles.length;
  els.mergeButton.disabled = locked || mergeFiles.length < 2 || !els.mergeOutput.value.trim();
  els.openMergeOutput.disabled = locked || !mergeState.finished || !els.mergeOutput.value.trim();
  els.mergeDropZone.classList.toggle("flow-locked", locked);
  $$(".merge-icon-button").forEach((button) => {
    button.disabled = locked || button.dataset.unavailable === "true";
  });
  $$(".merge-file-row").forEach((row) => {
    row.draggable = !locked;
  });
}

function moveMergeFile(fromIndex, toIndex) {
  if (mergeState.running || fromIndex === toIndex || fromIndex < 0 || toIndex < 0 || toIndex >= mergeFiles.length) return;
  const [moved] = mergeFiles.splice(fromIndex, 1);
  mergeFiles.splice(toIndex, 0, moved);
  mergeState.finished = false;
  mergeState.generation += 1;
  syncMergeOutput();
  setResult(els.mergeResult, "");
  resetMergeProgress();
  renderMergeFiles();
}

function removeMergeFile(index) {
  if (mergeState.running || index < 0 || index >= mergeFiles.length) return;
  mergeFiles.splice(index, 1);
  mergeState.finished = false;
  mergeState.generation += 1;
  syncMergeOutput();
  setResult(els.mergeResult, "");
  resetMergeProgress();
  renderMergeFiles();
}

function mergeIconButton(symbol, label, onClick, unavailable = false, extraClass = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `merge-icon-button${extraClass ? ` ${extraClass}` : ""}`;
  button.textContent = symbol;
  button.setAttribute("aria-label", label);
  button.title = label;
  button.dataset.unavailable = String(unavailable);
  button.disabled = mergeState.running || unavailable;
  button.addEventListener("click", onClick);
  return button;
}

function renderMergeFiles() {
  els.mergeFileList.replaceChildren();
  els.mergeFileCount.textContent = mergeCountLabel(mergeFiles.length);
  els.mergeEmptyState.hidden = mergeFiles.length > 0;
  els.mergeFileList.hidden = mergeFiles.length === 0;

  mergeFiles.forEach((filePath, index) => {
    const row = document.createElement("li");
    row.className = "merge-file-row";
    row.dataset.index = String(index);
    row.draggable = !mergeState.running;
    row.title = filePath;

    const handle = document.createElement("div");
    handle.className = "merge-drag-handle";
    handle.textContent = "⋮⋮";
    handle.setAttribute("aria-hidden", "true");

    const order = document.createElement("div");
    order.className = "merge-order";
    order.textContent = String(index + 1);

    const info = document.createElement("div");
    info.className = "merge-file-info";
    const name = document.createElement("div");
    name.className = "merge-file-name";
    name.textContent = basename(filePath);
    const type = document.createElement("div");
    type.className = "merge-file-type";
    type.textContent = fileExtension(filePath) || "arquivo";
    info.append(name, type);

    const actions = document.createElement("div");
    actions.className = "merge-file-actions";
    actions.append(
      mergeIconButton("↑", "Mover para cima", () => moveMergeFile(index, index - 1), index === 0),
      mergeIconButton("↓", "Mover para baixo", () => moveMergeFile(index, index + 1), index === mergeFiles.length - 1),
      mergeIconButton("×", "Remover arquivo", () => removeMergeFile(index), false, "merge-remove-button")
    );
    row.append(handle, order, info, actions);

    row.addEventListener("dragstart", (event) => {
      if (mergeState.running) return event.preventDefault();
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/x-pdfutils-merge-index", String(index));
      row.classList.add("dragging");
    });
    row.addEventListener("dragend", () => {
      row.classList.remove("dragging");
      $$(".merge-file-row").forEach((item) => item.classList.remove("drag-target"));
    });
    row.addEventListener("dragover", (event) => {
      if (mergeState.running || Array.from(event.dataTransfer.types || []).includes("Files")) return;
      event.preventDefault();
      row.classList.add("drag-target");
      event.dataTransfer.dropEffect = "move";
    });
    row.addEventListener("dragleave", () => row.classList.remove("drag-target"));
    row.addEventListener("drop", (event) => {
      if (mergeState.running || Array.from(event.dataTransfer.types || []).includes("Files")) return;
      event.preventDefault();
      row.classList.remove("drag-target");
      const fromIndex = Number(event.dataTransfer.getData("text/x-pdfutils-merge-index"));
      if (Number.isInteger(fromIndex)) moveMergeFile(fromIndex, index);
    });
    els.mergeFileList.appendChild(row);
  });
  updateMergeControls();
}

function addMergePaths(paths) {
  if (mergeState.running) return;
  const accepted = [];
  const rejected = [];
  for (const rawPath of paths || []) {
    const filePath = String(rawPath || "").trim();
    if (!filePath) continue;
    if (!mergeFileExtensions.includes(fileExtension(filePath))) rejected.push(basename(filePath));
    else accepted.push(filePath);
  }
  if (accepted.length) {
    mergeFiles.push(...accepted);
    mergeState.finished = false;
    mergeState.generation += 1;
    syncMergeOutput();
    resetMergeProgress();
  }
  setResult(
    els.mergeResult,
    rejected.length ? `Arquivos não aceitos:\n${rejected.join("\n")}` : ""
  );
  renderMergeFiles();
  setStatus("Pronto.");
}

async function pickMergeFiles() {
  if (mergeState.running) return;
  const paths = await api.openFiles({
    title: "Adicionar arquivos ao PDF",
    filters: mergeFileFilters
  });
  addMergePaths(paths);
}

async function pickMergeOutput() {
  if (mergeState.running || !mergeFiles.length) return;
  const filePath = await api.savePdf({
    title: "Salvar PDF unido",
    defaultPath: els.mergeOutput.value || defaultMergeOutputPath()
  });
  if (!filePath) return;
  els.mergeOutput.value = filePath;
  mergeOutputCustomized = true;
  mergeState.finished = false;
  updateMergeControls();
}

async function mergeSelectedFiles() {
  if (mergeState.running) return;
  if (mergeFiles.length < 2) {
    setResult(els.mergeResult, "Adicione pelo menos dois arquivos para juntar.");
    return;
  }
  if (!els.mergeOutput.value.trim()) {
    setResult(els.mergeResult, "Escolha o nome do PDF final.");
    return;
  }

  const operationId = newOnrOperationId();
  const generation = ++mergeState.generation;
  mergeState.running = true;
  mergeState.finished = false;
  mergeState.cancelRequested = false;
  mergeState.operationId = operationId;
  setResult(els.mergeResult, "");
  setMergeProgress(2, "Iniciando a junção dos arquivos...", { force: true });
  renderMergeFiles();
  setStatus("Processando...");

  try {
    const result = await api.mergeFilesToPdf({
      sourcePaths: [...mergeFiles],
      outputPath: els.mergeOutput.value.trim(),
      operationId
    });
    if (mergeState.generation !== generation) return;
    mergeState.finished = true;
    setMergeProgress(100, "PDF final criado com sucesso.", { force: true });
    setResult(
      els.mergeResult,
      `PDF criado:\n${result.output}\n\nArquivos: ${result.sourceCount}\nPáginas: ${result.pageCount}`
    );
    setStatus("Pronto.");
  } catch (error) {
    if (mergeState.generation === generation) {
      await reportError(els.mergeResult, error, { action: "mergeFilesToPdf", files: mergeFiles.length });
      setMergeProgress(
        0,
        mergeState.cancelRequested ? "Junção cancelada." : "Junção não concluída.",
        { force: true }
      );
    }
  } finally {
    if (mergeState.generation === generation) {
      mergeState.running = false;
      mergeState.operationId = "";
      els.cancelMergeButton.hidden = true;
      renderMergeFiles();
    }
  }
}

async function cancelMerge() {
  if (!mergeState.running || !mergeState.operationId || mergeState.cancelRequested) return;
  mergeState.cancelRequested = true;
  els.cancelMergeButton.disabled = true;
  setMergeProgress(
    Number(els.mergeProgressTrack.getAttribute("aria-valuenow")) || 0,
    "Cancelando junção...",
    { force: true }
  );
  await api.cancelWorkflow(mergeState.operationId).catch(() => false);
}

async function resetMergeFlow() {
  const operationId = mergeState.operationId;
  mergeState.generation += 1;
  mergeState.running = false;
  mergeState.finished = false;
  mergeState.cancelRequested = false;
  mergeState.operationId = "";
  mergeFiles = [];
  mergeOutputCustomized = false;
  els.mergeOutput.value = "";
  setResult(els.mergeResult, "");
  resetMergeProgress();
  renderMergeFiles();
  if (operationId) await api.cancelWorkflow(operationId).catch(() => false);
}

function wireMergeDrop() {
  const clearDragState = () => els.mergeDropZone.classList.remove("drag-over");
  els.mergeDropZone.addEventListener("dragenter", (event) => {
    event.preventDefault();
    if (!mergeState.running) els.mergeDropZone.classList.add("drag-over");
  });
  els.mergeDropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = mergeState.running ? "none" : "copy";
  });
  els.mergeDropZone.addEventListener("dragleave", (event) => {
    if (!els.mergeDropZone.contains(event.relatedTarget)) clearDragState();
  });
  els.mergeDropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    clearDragState();
    if (mergeState.running) return;
    const paths = Array.from(event.dataTransfer.files || []).map((file) => api.pathForFile(file));
    addMergePaths(paths);
  });
}

function canSelectFlowFile(name) {
  const state = fileFlowStates[name];
  return Boolean(state && !state.running && (!state.selected || state.finished));
}

function updateFileFlowControls(name) {
  const flow = fileFlows[name];
  const state = fileFlowStates[name];
  if (!flow || !state) return;
  const canSelect = canSelectFlowFile(name);
  flow.pickButton.disabled = !canSelect;
  flow.processButton.disabled = state.running || !state.selected;
  for (const control of flow.controlsDuringRun || []) {
    if (control) control.disabled = state.running;
  }
  const dropTarget = document.querySelector(`[data-file-flow="${name}"]`);
  dropTarget?.classList.toggle("flow-locked", !canSelect);
}

function clearFlowResult(name) {
  const flow = fileFlows[name];
  if (flow?.result) setResult(flow.result, "");
  if (name === "validate") {
    els.validateBadge.className = "badge neutral";
    els.validateBadge.textContent = "Aguardando";
  }
}

function resetProgress(name) {
  const progress = progressFlows[name];
  if (!progress) return;
  progress.container.hidden = true;
  progress.label.textContent = "";
  progress.value.textContent = "0%";
  progress.bar.style.width = "0%";
  progress.track.setAttribute("aria-valuenow", "0");
  progress.cancelButton.hidden = false;
  progress.cancelButton.disabled = false;
}

function applySelectedFile(name, filePath) {
  const flow = fileFlows[name];
  const state = fileFlowStates[name];
  const normalizedPath = String(filePath || "").trim();
  if (!flow || !state || !normalizedPath || !canSelectFlowFile(name)) return false;
  const extension = fileExtension(normalizedPath);
  if (!flow.extensions.includes(extension)) {
    setResult(flow.result, `Tipo de arquivo não aceito: .${extension || "sem extensão"}`);
    return false;
  }

  flow.source.value = normalizedPath;
  if (flow.output) flow.output.value = defaultOutputPath(normalizedPath, flow.outputSuffix);
  if (flow.derivedTitle) flow.derivedTitle.value = withoutExt(basename(normalizedPath));
  state.selected = true;
  state.running = false;
  state.finished = false;
  state.cancelRequested = false;
  state.operationId = "";
  state.generation += 1;
  clearFlowResult(name);
  resetProgress(name);
  setStatus("Pronto.");
  if (name === "sign-onr") {
    completedOnrSignature = null;
    setOnrActionMode("idle");
  }
  updateFileFlowControls(name);
  return true;
}

async function pickFlowSource(name) {
  const flow = fileFlows[name];
  if (!flow || !canSelectFlowFile(name)) return "";
  const filePath = await api.openFile({ title: flow.title, filters: flow.filters });
  if (!filePath) return "";
  return applySelectedFile(name, filePath) ? filePath : "";
}

function beginFileFlow(name, operationId = "") {
  const state = fileFlowStates[name];
  if (!state?.selected) throw new Error("Escolha um arquivo para continuar.");
  state.running = true;
  state.finished = false;
  state.cancelRequested = false;
  state.operationId = operationId;
  updateFileFlowControls(name);
  return state.generation;
}

function finishFileFlow(name, generation) {
  const state = fileFlowStates[name];
  if (!state || state.generation !== generation) return;
  state.running = false;
  state.finished = true;
  state.operationId = "";
  if (progressFlows[name]) progressFlows[name].cancelButton.hidden = true;
  updateFileFlowControls(name);
}

function isCurrentFileFlow(name, generation) {
  return fileFlowStates[name]?.generation === generation;
}

async function runFileTask(name, context, operationId, task) {
  const flow = fileFlows[name];
  let generation;
  try {
    generation = beginFileFlow(name, operationId);
  } catch (error) {
    await reportError(flow.result, error, context);
    return null;
  }

  setStatus("Processando...");
  try {
    const result = await task(generation);
    if (fileFlowStates[name].generation === generation) setStatus("Pronto.");
    return result;
  } catch (error) {
    if (fileFlowStates[name].generation === generation) {
      await reportError(flow.result, error, context);
    }
    return null;
  } finally {
    finishFileFlow(name, generation);
  }
}

async function resetFileFlow(name) {
  const flow = fileFlows[name];
  const state = fileFlowStates[name];
  if (!flow || !state) return;
  const operationId = state.operationId;
  state.generation += 1;
  state.selected = false;
  state.running = false;
  state.finished = false;
  state.cancelRequested = false;
  state.operationId = "";
  flow.source.value = "";
  if (flow.output) flow.output.value = "";
  if (flow.derivedTitle) flow.derivedTitle.value = "";
  if (name === "convert") {
    activeConvertOperationId = "";
    convertCancelRequested = false;
  }
  if (name === "sign-pdf") {
    els.signCertificate.value = "";
    activeSignOperationId = "";
    signCancelRequested = false;
  }
  if (name === "sign-onr") {
    els.onrCertificate.value = "";
    completedOnrSignature = null;
    activeOnrOperationId = "";
    onrCancelRequested = false;
    setOnrActionMode("idle");
  }
  clearFlowResult(name);
  resetProgress(name);
  updateFileFlowControls(name);
  if (operationId) await api.cancelWorkflow(operationId).catch(() => false);
}

function setFlowProgress(name, percent, message, options = {}) {
  const state = fileFlowStates[name];
  const progress = progressFlows[name];
  if (!progress || (!state.running && !options.force)) return;
  const value = Math.max(0, Math.min(100, Math.round(Number(percent) || 0)));
  progress.container.hidden = Boolean(options.hidden);
  progress.label.textContent = message || "Processando...";
  progress.value.textContent = `${value}%`;
  progress.bar.style.width = `${value}%`;
  progress.track.setAttribute("aria-valuenow", String(value));
  if (value >= 100) progress.cancelButton.hidden = true;
  if (message && options.log && fileFlows[name]?.result) appendResult(fileFlows[name].result, message);
}

async function cancelFileFlow(name, message) {
  const state = fileFlowStates[name];
  const progress = progressFlows[name];
  if (!state?.running || !state.operationId || state.cancelRequested) return;
  state.cancelRequested = true;
  if (progress) progress.cancelButton.disabled = true;
  setFlowProgress(name, Number(progress?.track.getAttribute("aria-valuenow")) || 0, message || "Cancelando...", { force: true });
  await api.cancelWorkflow(state.operationId).catch(() => false);
}

function wireFileDrops() {
  document.addEventListener("dragover", (event) => event.preventDefault());
  document.addEventListener("drop", (event) => event.preventDefault());
  $$("[data-file-flow]").forEach((target) => {
    const name = target.dataset.fileFlow;
    const clearDragState = () => target.classList.remove("drag-over");
    target.addEventListener("dragenter", (event) => {
      event.preventDefault();
      if (canSelectFlowFile(name)) target.classList.add("drag-over");
    });
    target.addEventListener("dragover", (event) => {
      event.preventDefault();
      if (canSelectFlowFile(name)) event.dataTransfer.dropEffect = "copy";
      else event.dataTransfer.dropEffect = "none";
    });
    target.addEventListener("dragleave", clearDragState);
    target.addEventListener("drop", (event) => {
      event.preventDefault();
      clearDragState();
      if (!canSelectFlowFile(name)) return;
      const file = event.dataTransfer.files?.[0];
      if (!file) return;
      const filePath = api.pathForFile(file);
      applySelectedFile(name, filePath);
    });
  });
}

function certLabel(cert) {
  const br = cert.pkiBrazil || {};
  const id = br.cpf || br.cnpj || "";
  const end = cert.validityEnd ? new Date(cert.validityEnd).toLocaleDateString("pt-BR") : "";
  return [cert.subjectName || cert.subjectDN || "Certificado", id, end ? `válido até ${end}` : ""].filter(Boolean).join(" - ");
}

function isUsableCertificate(cert) {
  const validityEnd = cert.validityEnd ? new Date(cert.validityEnd) : null;
  if (validityEnd && validityEnd < new Date()) return false;
  const certificateType = cert.pkiBrazil?.certificateType || "";
  if (certificateType && certificateType !== "A3") return false;
  if (!certificateType || certificateType === "Unknown") return false;
  const usage = cert.keyUsage || {};
  if (usage.digitalSignature || usage.nonRepudiation) return true;
  return Object.keys(usage).length === 0;
}

function renderCertificates(select = null) {
  const targets = (select ? [select] : [els.signCertificate, els.onrCertificate]).filter(Boolean);
  for (const target of targets) {
    const previous = target.value;
    target.innerHTML = "";
    const empty = document.createElement("option");
    empty.value = "";
    empty.textContent = certificates.length ? "Selecione um certificado" : "Nenhum certificado carregado";
    target.appendChild(empty);
    for (const cert of certificates) {
      const option = document.createElement("option");
      option.value = cert.thumbprint;
      option.textContent = certLabel(cert);
      target.appendChild(option);
    }
    if (previous && certificates.some((cert) => cert.thumbprint === previous)) target.value = previous;
  }
}

function getSelectedCertificate(select) {
  const thumbprint = select.value;
  return certificates.find((cert) => cert.thumbprint === thumbprint) || null;
}

async function refreshCertificates(targetSelect, resultElement) {
  const listed = await api.listCertificates();
  certificates = listed.filter(isUsableCertificate);
  renderCertificates();
  if (false && !certificates.length) {
    throw new Error("Não foram encontrados certificados digitais válidos para assinatura");
  }
  setResult(resultElement, `${certificates.length} certificado(s) carregado(s).`);
}

function formatGhostscriptStatus(status) {
  if (status?.installed) {
    const version = status.version ? ` v${status.version}` : "";
    return `Ghostscript instalado${version}.\n${status.executable}`;
  }
  return "Ghostscript não instalado. Ele é necessário para converter documentos em PDF/A.";
}

async function refreshGhostscriptStatus(resultElement = null) {
  const status = await api.ghostscriptStatus();
  els.ghostscriptStatus.textContent = formatGhostscriptStatus(status);
  els.installGhostscript.disabled = Boolean(status.installed);
  if (resultElement) appendResult(resultElement, formatGhostscriptStatus(status));
  return status;
}

async function runGhostscriptInstaller(resultElement, options = {}) {
  const result = await api.installGhostscript(options);
  await refreshGhostscriptStatus();
  if (result.canceled) {
    appendResult(resultElement, "Instalação do Ghostscript cancelada.");
    return false;
  }
  if (result.installed && !result.launched) {
    appendResult(resultElement, formatGhostscriptStatus(result));
    return true;
  }
  appendResult(resultElement, result.message || "Instalador do Ghostscript aberto. Conclua a instalação e tente novamente.");
  setStatus("Instale o Ghostscript para continuar.");
  return false;
}

async function ensureGhostscript(resultElement) {
  const status = await refreshGhostscriptStatus();
  if (status.installed) return true;
  appendResult(resultElement, "Ghostscript não encontrado.");
  return runGhostscriptInstaller(resultElement, { confirm: true });
}

async function pickSave(input, defaultPath, title) {
  const filePath = await api.savePdf({ title, defaultPath });
  if (filePath) input.value = filePath;
}

let lastOnrProgressMessage = "";

function setOnrActionMode(mode) {
  els.cancelOnrButton.hidden = mode !== "running";
  els.cancelOnrButton.disabled = false;
  els.onrCompleteActions.hidden = mode !== "complete";
}

function setOnrProgress(percent, message, options = {}) {
  const value = Math.max(0, Math.min(100, Math.round(Number(percent) || 0)));
  if (!fileFlowStates["sign-onr"].running && !options.force) return;
  setFlowProgress("sign-onr", value, message || "Processando assinatura ONR...", {
    hidden: options.hidden,
    force: options.force
  });
  if (message && options.log !== false && message !== lastOnrProgressMessage) {
    lastOnrProgressMessage = message;
    appendResult(els.onrResult, message);
  }
}

function newOnrOperationId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function assertOnrNotCancelled() {
  if (!onrCancelRequested) return;
  throw new Error("Assinatura ONR cancelada pelo usuário.");
}

async function loadAndRenderOnrHistory() {
  try {
    onrHistoryItems = await api.loadOnrHistory();
  } catch {
    onrHistoryItems = [];
  }
  renderOnrHistory();
}

function renderOnrHistory() {
  if (!els.historyTableBody) return;

  const searchQuery = els.historySearch.value || "";
  const dateFrom = els.historyDateFrom.value ? new Date(els.historyDateFrom.value + "T00:00:00") : null;
  const dateTo = els.historyDateTo.value ? new Date(els.historyDateTo.value + "T23:59:59") : null;
  const sortBy = els.historySortBy.value;
  const pageSize = parseInt(els.historyPageSize.value, 10) || 50;

  // Filtragem com suporte a similaridade e busca nas 3 colunas
  let filtered = onrHistoryItems.filter((item) => {
    if (!matchesHistorySearch(item, searchQuery)) return false;
    const itemDate = new Date(item.signedAt);
    if (dateFrom && itemDate < dateFrom) return false;
    if (dateTo && itemDate > dateTo) return false;
    return true;
  });

  // Ordenação
  filtered.sort((a, b) => {
    if (sortBy === "date-desc") return new Date(b.signedAt) - new Date(a.signedAt);
    if (sortBy === "date-asc") return new Date(a.signedAt) - new Date(b.signedAt);
    if (sortBy === "name-asc") return (a.fileName || "").localeCompare(b.fileName || "");
    if (sortBy === "name-desc") return (b.fileName || "").localeCompare(a.fileName || "");
    return 0;
  });

  // Paginação
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  if (onrHistoryCurrentPage > totalPages) onrHistoryCurrentPage = totalPages;
  if (onrHistoryCurrentPage < 1) onrHistoryCurrentPage = 1;

  const startIndex = (onrHistoryCurrentPage - 1) * pageSize;
  const paginatedItems = filtered.slice(startIndex, startIndex + pageSize);

  els.historyTableBody.replaceChildren();
  if (paginatedItems.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 3;
    td.style.textAlign = "center";
    td.style.color = "var(--muted)";
    td.textContent = "Nenhum documento encontrado no histórico.";
    tr.appendChild(td);
    els.historyTableBody.appendChild(tr);
  } else {
    for (const item of paginatedItems) {
      const tr = document.createElement("tr");

      const tdName = document.createElement("td");
      tdName.textContent = item.fileName || "Documento";

      const tdLink = document.createElement("td");
      if (item.endpointLink) {
        const a = document.createElement("a");
        a.href = "#";
        a.textContent = item.endpointLink;
        a.title = "Abrir link na ONR";
        a.addEventListener("click", (e) => {
          e.preventDefault();
          api.openExternal(item.endpointLink);
        });
        tdLink.appendChild(a);
      } else {
        tdLink.textContent = "-";
      }

      const tdDate = document.createElement("td");
      tdDate.textContent = item.signedAt ? new Date(item.signedAt).toLocaleString("pt-BR") : "-";

      tr.append(tdName, tdLink, tdDate);
      els.historyTableBody.appendChild(tr);
    }
  }

  els.historyPageInfo.textContent = `Página ${onrHistoryCurrentPage} de ${totalPages} (${filtered.length} registros)`;
  els.historyPrevPage.disabled = onrHistoryCurrentPage <= 1;
  els.historyNextPage.disabled = onrHistoryCurrentPage >= totalPages;
}

// Configuração dos Listeners de Eventos do Histórico
if (els.historySearch) {
  els.historySearch.addEventListener("input", () => {
    onrHistoryCurrentPage = 1;
    renderOnrHistory();
  });
  els.historyDateFrom.addEventListener("change", () => {
    onrHistoryCurrentPage = 1;
    renderOnrHistory();
  });
  els.historyDateTo.addEventListener("change", () => {
    onrHistoryCurrentPage = 1;
    renderOnrHistory();
  });
  els.historySortBy.addEventListener("change", () => {
    renderOnrHistory();
  });
  els.historyPageSize.addEventListener("change", () => {
    onrHistoryCurrentPage = 1;
    renderOnrHistory();
  });
  els.historyPrevPage.addEventListener("click", () => {
    if (onrHistoryCurrentPage > 1) {
      onrHistoryCurrentPage--;
      renderOnrHistory();
    }
  });
  els.historyNextPage.addEventListener("click", () => {
    onrHistoryCurrentPage++;
    renderOnrHistory();
  });
}

function formValue(element, fallback = "") {
  return element ? element.value.trim() : String(fallback || "").trim();
}

function configFromForm() {
  return {
    ...config,
    webPkiInstallerUrl: formValue(els.webPkiInstallerUrl, config.webPkiInstallerUrl),
    webPkiLicense: formValue(els.webPkiLicense, config.webPkiLicense),
    onrBaseUrl: formValue(els.onrBaseUrl, config.onrBaseUrl),
    onrPortalUrl: formValue(els.onrPortalUrl, config.onrPortalUrl),
    onrStartEndpoint: formValue(els.onrStartEndpoint, config.onrStartEndpoint),
    onrCompleteEndpoint: formValue(els.onrCompleteEndpoint, config.onrCompleteEndpoint),
    onrUploadBytesEndpoint: formValue(els.onrUploadBytesEndpoint, config.onrUploadBytesEndpoint),
    onrUseUploadBytes: els.onrUseUploadBytes ? els.onrUseUploadBytes.checked : Boolean(config.onrUseUploadBytes),
    onrSubscription: formValue(els.onrSubscription, config.onrSubscription),
    onrApiKey: formValue(els.onrApiKey, config.onrApiKey),
    onrOutputFolder: formValue(els.onrOutputFolder, config.onrOutputFolder),
    onrBearerToken: formValue(els.onrBearerToken, config.onrBearerToken),
    onrExtraHeadersJson: formValue(els.onrExtraHeadersJson, config.onrExtraHeadersJson || "{}") || "{}"
  };
}

function fillConfigForm(nextConfig) {
  if (els.webPkiInstallerUrl) els.webPkiInstallerUrl.value = nextConfig.webPkiInstallerUrl || "";
  if (els.webPkiLicense) els.webPkiLicense.value = nextConfig.webPkiLicense || "";
  if (els.onrBaseUrl) els.onrBaseUrl.value = nextConfig.onrBaseUrl || "";
  if (els.onrPortalUrl) els.onrPortalUrl.value = nextConfig.onrPortalUrl || "";
  if (els.onrStartEndpoint) els.onrStartEndpoint.value = nextConfig.onrStartEndpoint || "";
  if (els.onrCompleteEndpoint) els.onrCompleteEndpoint.value = nextConfig.onrCompleteEndpoint || "";
  if (els.onrUploadBytesEndpoint) els.onrUploadBytesEndpoint.value = nextConfig.onrUploadBytesEndpoint || "";
  if (els.onrUseUploadBytes) els.onrUseUploadBytes.checked = Boolean(nextConfig.onrUseUploadBytes);
  if (els.onrSubscription) els.onrSubscription.value = nextConfig.onrSubscription || "";
  if (els.onrApiKey) els.onrApiKey.value = nextConfig.onrApiKey || "";
  if (els.onrOutputFolder) els.onrOutputFolder.value = nextConfig.onrOutputFolder || "";
  if (els.onrBearerToken) els.onrBearerToken.value = nextConfig.onrBearerToken || "";
  if (els.onrExtraHeadersJson) els.onrExtraHeadersJson.value = nextConfig.onrExtraHeadersJson || "{}";
}

function hasOnrCredential(nextConfig) {
  return Boolean(
    String(nextConfig.onrApiKey || "").trim()
    || String(nextConfig.onrBearerToken || "").trim()
    || String(nextConfig.onrCookieHeader || "").trim()
  );
}

async function performOnrCertificateLogin(resultElement) {
  const savedConfig = await api.saveConfig(configFromForm());
  config = savedConfig;
  fillConfigForm(config);
  appendResult(resultElement, "Abrindo login ONR...");
  const result = await api.loginOnr({ config });
  config = result.config || { ...config, onrBearerToken: result.accessToken };
  fillConfigForm(config);
  const expires = result.expiresAt ? ` Expira em ${new Date(result.expiresAt).toLocaleString("pt-BR")}.` : "";
  appendResult(resultElement, `Login ONR concluído.${expires}`);
  return result;
}

async function loginOnr() {
  setResult(els.settingsResult, "");
  await runTask(els.loginOnr, els.settingsResult, { action: "loginOnr" }, async () => {
    const result = await performOnrCertificateLogin(els.settingsResult);
    const expires = result.expiresAt ? `\nExpira em: ${new Date(result.expiresAt).toLocaleString("pt-BR")}` : "";
    setResult(els.settingsResult, `Login ONR concluído. Credenciais de sessão salvas.${expires}`);
  });
}

async function clearOnrToken() {
  els.onrBearerToken.value = "";
  config = await api.saveConfig({
    ...configFromForm(),
    onrCookieHeader: "",
    onrLoginStorageJson: "{}"
  });
  fillConfigForm(config);
  setResult(els.settingsResult, "Credenciais de sessão ONR removidas.");
}

async function convertToPdfA() {
  setResult(els.convertResult, "");
  const operationId = newOnrOperationId();
  const flowGeneration = fileFlowStates.convert.generation;
  activeConvertOperationId = operationId;
  convertCancelRequested = false;
  setFlowProgress("convert", 2, "Iniciando conversão para PDF/A...", { force: true });
  const completed = await runFileTask("convert", { action: "convertToPdfA" }, operationId, async (generation) => {
    if (!(await ensureGhostscript(els.convertResult))) return;
    if (!isCurrentFileFlow("convert", generation)) return false;
    if (fileFlowStates.convert.cancelRequested) throw new Error("Conversão para PDF/A cancelada pelo usuário.");
    const result = await api.convertToPdfA({
      sourcePath: els.convertSource.value.trim(),
      outputPath: els.convertOutput.value.trim(),
      operationId
    });
    if (!isCurrentFileFlow("convert", generation)) return false;
    const warning = result.warning ? `\n\n${result.warning}` : "";
    setResult(els.convertResult, `PDF/A criado:\n${result.output}\n\nPadrão: ${result.selectedPdfA || "PDF/A"}${warning}`);
    setFlowProgress("convert", 100, "Conversão para PDF/A concluída.", { force: true });
    return true;
  });
  activeConvertOperationId = "";
  if (!completed && fileFlowStates.convert.generation === flowGeneration) {
    setFlowProgress(
      "convert",
      0,
      convertCancelRequested ? "Conversão cancelada." : "Conversão não concluída.",
      { force: true }
    );
  }
}

async function validatePdfA() {
  setResult(els.validateResult, "");
  els.validateBadge.className = "badge neutral";
  els.validateBadge.textContent = "Validando";
  await runFileTask("validate", { action: "validatePdfA" }, "", async (generation) => {
    const result = await api.validatePdfA({ sourcePath: els.validateSource.value.trim() });
    if (!isCurrentFileFlow("validate", generation)) return;
    els.validateBadge.className = `badge ${result.isPdfA ? "ok" : "fail"}`;
    els.validateBadge.textContent = result.isPdfA ? "PDF/A válido" : "Não é PDF/A";
    setResult(els.validateResult, result.details || JSON.stringify(result, null, 2));
  });
}

function formatSignatureDate(value) {
  if (!value) return "não informada";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "não informada";
  return date.toLocaleString("pt-BR");
}

function formatSignatureTrust(signature) {
  if (signature.trustStatus === "trusted") {
    if (signature.revocationStatus === "valid") {
      return "cadeia confiável e revogação verificada";
    }
    if (signature.revocationStatus === "unknown") {
      return "cadeia confiável; não foi possível confirmar a revogação";
    }
    return "cadeia confiável pelo Windows";
  }
  if (signature.trustStatus === "untrusted") {
    return "integridade confirmada; cadeia não reconhecida pelo Windows";
  }
  return "integridade confirmada; confiança não pôde ser verificada";
}

function formatValidatedSignature(signature) {
  const lines = [
    signature.documentTimestamp
      ? `Carimbo do tempo: ${signature.name || "Autoridade não identificada"}`
      : (signature.name || "Assinante não identificado"),
    signature.documentTimestamp ? "Status: válido" : "Status: válida",
    `Tipo: ${signature.format || "Assinatura digital PDF"}`,
    `CPF: ${signature.cpf || "não informado"}`,
    `Nº de série do certificado: ${signature.certificateSerialNumber || "não informado"}`,
    `Emissor do certificado: ${signature.certificateIssuer || "não informado"}`,
    `${signature.documentTimestamp ? "Data do carimbo" : "Data da Assinatura"}: ${formatSignatureDate(signature.signingTime)}`,
    "Integridade: documento íntegro no conteúdo assinado",
    `Confiança: ${formatSignatureTrust(signature)}`
  ];
  if (signature.timestampPresent && !signature.documentTimestamp) {
    lines.push(
      `Carimbo do tempo: ${signature.timestampValid ? "válido" : "não validado"}${signature.timestampAuthority ? ` (${signature.timestampAuthority})` : ""}`
    );
  }
  if (signature.hasLaterRevisions) {
    lines.push("Revisões: o PDF recebeu uma atualização incremental após esta assinatura");
  }
  if (signature.hasLongTermValidationData) {
    lines.push("Dados de validação de longo prazo: presentes no PDF");
  }
  return lines.join("\n");
}

async function validateSignatures() {
  setResult(els.signatureValidationResult, "");
  await runFileTask("validate-signatures", { action: "validateSignatures" }, "", async (generation) => {
    const result = await api.validateSignatures({ sourcePath: els.signatureValidationSource.value.trim() });
    if (!isCurrentFileFlow("validate-signatures", generation)) return;
    const signatures = (result.signatures || []).filter((signature) => signature.valid);
    if (!signatures.length) {
      setResult(els.signatureValidationResult, "Sem assinaturas válidas");
      return;
    }
    setResult(els.signatureValidationResult, signatures.map(formatValidatedSignature).join("\n\n"));
  });
}

async function signPdf() {
  setResult(els.signResult, "");
  const operationId = newOnrOperationId();
  const flowGeneration = fileFlowStates["sign-pdf"].generation;
  activeSignOperationId = operationId;
  signCancelRequested = false;
  setFlowProgress("sign-pdf", 2, "Iniciando assinatura do PDF...", { force: true });
  const completed = await runFileTask("sign-pdf", { action: "signPdf" }, operationId, async (generation) => {
    const sourcePath = els.signSource.value.trim();
    const outputPath = els.signOutput.value.trim();
    const cert = getSelectedCertificate(els.signCertificate);
    if (!outputPath) throw new Error("Escolha o arquivo de saída para o PDF assinado.");
    if (!cert && !certificates.length) throw new Error("Não foram encontrados certificados digitais válidos para assinatura");
    if (!cert) throw new Error("Selecione um certificado digital válido para assinatura.");
    if (!(await ensureGhostscript(els.signResult))) return;
    if (!isCurrentFileFlow("sign-pdf", generation)) return false;
    if (fileFlowStates["sign-pdf"].cancelRequested) throw new Error("Assinatura do PDF cancelada pelo usuário.");

    config = configFromForm();
    const result = await api.signPdfSession({
      config,
      sourcePath,
      outputPath,
      outputBaseName: withoutExt(basename(outputPath || sourcePath)),
      certificateThumbprint: cert.thumbprint,
      operationId
    });
    if (!isCurrentFileFlow("sign-pdf", generation)) return false;
    setResult(els.signResult, `PDF assinado:\n${result.output}`);
    setFlowProgress("sign-pdf", 100, "Assinatura do PDF concluída.", { force: true });
    return true;
  });
  activeSignOperationId = "";
  if (!completed && fileFlowStates["sign-pdf"].generation === flowGeneration) {
    setFlowProgress(
      "sign-pdf",
      0,
      signCancelRequested ? "Assinatura cancelada." : "Assinatura não concluída.",
      { force: true }
    );
  }
}

async function cancelConvert() {
  if (!activeConvertOperationId) return;
  convertCancelRequested = true;
  await cancelFileFlow("convert", "Cancelando conversão...");
}

async function cancelSignPdf() {
  if (!activeSignOperationId) return;
  signCancelRequested = true;
  await cancelFileFlow("sign-pdf", "Cancelando assinatura...");
}

async function signOnr() {
  setResult(els.onrResult, "");
  lastOnrProgressMessage = "";
  completedOnrSignature = null;
  onrCancelRequested = false;
  activeOnrOperationId = newOnrOperationId();
  const flowGeneration = fileFlowStates["sign-onr"].generation;
  setOnrActionMode("running");
  setFlowProgress("sign-onr", 2, "Iniciando assinatura ONR...", { force: true });
  const completed = await runFileTask("sign-onr", { action: "signOnr" }, activeOnrOperationId, async (generation) => {
    config = configFromForm();
    const sourcePath = els.onrSource.value.trim();
    const title = els.onrTitle.value.trim() || withoutExt(basename(sourcePath));
    const cert = getSelectedCertificate(els.onrCertificate);
    if (!String(config.onrApiKey || "").trim()) {
      throw new Error("Configure a API Key (X-Api-Key) da ONR nas Configurações antes de assinar.");
    }
    if (!sourcePath) throw new Error("Escolha o PDF que será assinado pela ONR.");
    if (!cert && !certificates.length) throw new Error("Não foram encontrados certificados digitais válidos para assinatura");
    if (!cert) throw new Error("Selecione um certificado digital válido para assinatura.");

    setOnrProgress(7, "Verificando os componentes necessários...");
    if (!(await ensureGhostscript(els.onrResult))) return;
    if (!isCurrentFileFlow("sign-onr", generation)) return false;
    assertOnrNotCancelled();

    const result = await api.onrSignatureSession({
      config,
      title,
      fileName: `${title}.pdf`,
      sourcePath,
      certificateThumbprint: cert.thumbprint,
      operationId: activeOnrOperationId
    });
    if (!isCurrentFileFlow("sign-onr", generation)) return false;
    assertOnrNotCancelled();
    if (!result?.signedBase64) throw new Error("A ONR não retornou o PDF assinado.");

    completedOnrSignature = {
      sourcePath,
      outputFolder: config.onrOutputFolder,
      outputBaseName: title,
      signedBase64: result.signedBase64,
      output: "",
      documentKey: result.documentKey || "",
      formattedDocumentKey: result.formattedDocumentKey || result.documentKey || "",
      validationUrl: result.validationUrl || ""
    };
    const documentId = result.documentId ? `\nDocumento ONR: ${result.documentId}` : "";
    const validationCode = completedOnrSignature.formattedDocumentKey
      ? `\nCódigo de validação: ${completedOnrSignature.formattedDocumentKey}`
      : "";
    setOnrProgress(100, "Assinatura ONR concluída.", { log: false });
    setOnrActionMode("complete");
    setResult(els.onrResult, `Assinatura ONR concluída.${documentId}${validationCode}\n\nUse o botão de download para salvar o PDF assinado.`);
    return true;
  });
  activeOnrOperationId = "";
  if (!completed && fileFlowStates["sign-onr"].generation === flowGeneration) {
    setOnrActionMode("idle");
    setOnrProgress(
      0,
      onrCancelRequested ? "Assinatura ONR cancelada." : "Assinatura ONR não concluída.",
      { log: false, force: true }
    );
  }
}

async function cancelOnrSignature() {
  if (!activeOnrOperationId || completedOnrSignature) return;
  onrCancelRequested = true;
  await cancelFileFlow("sign-onr", "Cancelando assinatura ONR...");
}

async function downloadCompletedOnrSignature() {
  if (!completedOnrSignature) return;
  await runTask(els.downloadOnrButton, els.onrResult, { action: "downloadOnrSignature" }, async () => {
    if (!completedOnrSignature.output) {
      const saved = await api.saveSignedPdfAuto({
        sourcePath: completedOnrSignature.sourcePath,
        outputFolder: completedOnrSignature.outputFolder,
        outputBaseName: completedOnrSignature.outputBaseName,
        signedBase64: completedOnrSignature.signedBase64
      });
      completedOnrSignature.output = saved.output;
    }
    await api.showItemInFolder(completedOnrSignature.output);
    setResult(
      els.onrResult,
      `PDF assinado salvo em:\n${completedOnrSignature.output}\n\nCódigo de validação: ${completedOnrSignature.formattedDocumentKey || "não informado"}`
    );
  });
}

async function openCompletedOnrValidation() {
  if (!completedOnrSignature?.validationUrl) {
    setResult(els.onrResult, "A ONR não retornou um código de validação para este documento.");
    return;
  }
  await runTask(els.openOnrValidationButton, els.onrResult, { action: "openOnrValidation" }, async () => {
    await api.openExternal(completedOnrSignature.validationUrl);
  });
}

function wireEvents() {
  $$("[data-go]").forEach((button) => {
    button.addEventListener("click", async () => {
      const currentScreen = button.closest(".screen")?.id.replace(/^screen-/, "") || "";
      if (button.dataset.go === "menu" && fileFlows[currentScreen]) {
        await resetFileFlow(currentScreen);
      }
      if (button.dataset.go === "menu" && currentScreen === "merge") {
        await resetMergeFlow();
      }
      showScreen(button.dataset.go);
      if (button.dataset.go === "onr-history") {
        loadAndRenderOnrHistory();
      }
      if (button.dataset.go === "sign-onr" && !certificates.length && els.refreshOnrCertificates) {
        await runTask(
          els.refreshOnrCertificates,
          els.onrResult,
          { action: "refreshOnrCertificates" },
          () => refreshCertificates(els.onrCertificate, els.onrResult)
        );
      }
    });
  });

  els.pickConvertSource.addEventListener("click", () => pickFlowSource("convert"));
  els.pickConvertOutput.addEventListener("click", () => pickSave(els.convertOutput, els.convertOutput.value || defaultOutputPath(els.convertSource.value, " - PDF-A"), "Salvar PDF/A"));
  els.convertButton.addEventListener("click", convertToPdfA);
  els.cancelConvertButton.addEventListener("click", cancelConvert);
  els.openConvertOutput.addEventListener("click", () => els.convertOutput.value && api.openPath(els.convertOutput.value));

  els.addMergeFiles.addEventListener("click", pickMergeFiles);
  els.pickMergeOutput.addEventListener("click", pickMergeOutput);
  els.mergeButton.addEventListener("click", mergeSelectedFiles);
  els.cancelMergeButton.addEventListener("click", cancelMerge);
  els.openMergeOutput.addEventListener("click", () => els.mergeOutput.value && api.openPath(els.mergeOutput.value));

  els.pickValidateSource.addEventListener("click", () => pickFlowSource("validate"));
  els.validateButton.addEventListener("click", validatePdfA);

  els.pickSignatureValidationSource.addEventListener("click", () => pickFlowSource("validate-signatures"));
  els.validateSignaturesButton.addEventListener("click", validateSignatures);

  els.pickSignSource.addEventListener("click", () => pickFlowSource("sign-pdf"));
  els.pickSignOutput.addEventListener("click", () => pickSave(els.signOutput, els.signOutput.value || defaultOutputPath(els.signSource.value, " - assinado"), "Salvar PDF assinado"));
  els.refreshSignCertificates.addEventListener("click", () => runTask(els.refreshSignCertificates, els.signResult, { action: "refreshSignCertificates" }, () => refreshCertificates(els.signCertificate, els.signResult)));
  els.signPdfButton.addEventListener("click", signPdf);
  els.cancelSignButton.addEventListener("click", cancelSignPdf);
  els.openSignOutput.addEventListener("click", () => els.signOutput.value && api.openPath(els.signOutput.value));

  els.pickOnrSource.addEventListener("click", () => pickFlowSource("sign-onr"));
  if (els.refreshOnrCertificates) {
    els.refreshOnrCertificates.addEventListener("click", () => runTask(els.refreshOnrCertificates, els.onrResult, { action: "refreshOnrCertificates" }, () => refreshCertificates(els.onrCertificate, els.onrResult)));
  }
  els.signOnrButton.addEventListener("click", signOnr);
  els.cancelOnrButton.addEventListener("click", cancelOnrSignature);
  els.downloadOnrButton.addEventListener("click", downloadCompletedOnrSignature);
  els.openOnrValidationButton.addEventListener("click", openCompletedOnrValidation);

  if (els.pickOnrOutputFolder) {
    els.pickOnrOutputFolder.addEventListener("click", async () => {
      const folder = await api.openDirectory({
        title: "Pasta padrão para PDFs assinados pela ONR",
        defaultPath: els.onrOutputFolder.value || undefined
      });
      if (folder) els.onrOutputFolder.value = folder;
    });
  }
  if (els.clearOnrOutputFolder) {
    els.clearOnrOutputFolder.addEventListener("click", () => {
      els.onrOutputFolder.value = "";
    });
  }

  els.openWebPkiInstaller.addEventListener("click", () => {
    const url = els.webPkiInstallerUrl.value.trim() || config.webPkiInstallerUrl;
    if (url) api.openExternal(url);
  });
  els.installGhostscript.addEventListener("click", () => {
    runTask(els.installGhostscript, els.settingsResult, { action: "installGhostscript" }, () => runGhostscriptInstaller(els.settingsResult, { confirm: false }));
  });
  els.checkGhostscript.addEventListener("click", () => {
    runTask(els.checkGhostscript, els.settingsResult, { action: "checkGhostscript" }, () => refreshGhostscriptStatus(els.settingsResult));
  });
  if (els.loginOnr) els.loginOnr.addEventListener("click", loginOnr);
  if (els.clearOnrToken) els.clearOnrToken.addEventListener("click", clearOnrToken);
  els.saveSettings.addEventListener("click", async () => {
    await runTask(els.saveSettings, els.settingsResult, { action: "saveSettings" }, async () => {
      config = await api.saveConfig(configFromForm());
      fillConfigForm(config);
      setResult(els.settingsResult, "Configurações salvas.");
    });
  });

  els.checkUpdates.addEventListener("click", () => api.checkUpdates());
  els.installUpdate.addEventListener("click", () => api.installUpdate());
  els.themeToggle.addEventListener("click", toggleTheme);
  wireFileDrops();
  wireMergeDrop();

  api.onPdfAProgress((progress) => {
    const data = typeof progress === "string" ? { message: progress, percent: 0 } : progress || {};
    setFlowProgress("convert", data.percent, data.message);
  });
  api.onMergeProgress((progress) => {
    const data = typeof progress === "string" ? { message: progress, percent: 0 } : progress || {};
    setMergeProgress(data.percent, data.message);
  });
  api.onDependencyProgress((message) => {
    const target = $("#screen-settings").classList.contains("active")
      ? els.settingsResult
      : $("#screen-sign-onr").classList.contains("active")
        ? els.onrResult
        : $("#screen-sign-pdf").classList.contains("active")
          ? els.signResult
          : els.convertResult;
    appendResult(target, message);
  });
  api.onSignatureProgress((progress) => {
    const data = typeof progress === "string" ? { message: progress, percent: 0 } : progress || {};
    setFlowProgress("sign-pdf", data.percent, data.message);
  });
  api.onOnrProgress((progress) => {
    const data = typeof progress === "string" ? { message: progress, percent: 0 } : progress || {};
    setOnrProgress(data.percent, data.message);
  });
  api.onUpdateStatus((state) => {
    els.updateStatus.textContent = state.message || "Atualizações";
    els.installUpdate.hidden = !state.canInstall;
  });
}

async function init() {
  applyTheme(readTheme());
  els.version.textContent = `v${await api.version()}`;
  config = await api.loadConfig();
  fillConfigForm(config);
  renderCertificates();
  wireEvents();
  for (const name of Object.keys(fileFlows)) {
    resetProgress(name);
    updateFileFlowControls(name);
  }
  resetMergeProgress();
  renderMergeFiles();
  setOnrActionMode("idle");
  await refreshGhostscriptStatus();
  showScreen("menu");
}

init().catch(async (error) => {
  await reportError(els.settingsResult, error, { action: "init" });
});
