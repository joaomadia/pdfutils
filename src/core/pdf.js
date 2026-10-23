const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const childProcess = require("child_process");
const { pathToFileURL } = require("url");
const { PDFArray, PDFDocument, PDFName, degrees } = require("pdf-lib");

function safeFilename(value, fallback = "documento") {
  const cleaned = String(value || "")
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .replace(/[<>:"/\\|?*\n\r\t]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 130);
  return cleaned || fallback;
}

function ensurePdfExtension(filePath) {
  return path.extname(filePath).toLowerCase() === ".pdf" ? filePath : `${filePath}.pdf`;
}

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const parsed = path.parse(targetPath);
  let counter = 2;
  while (true) {
    const candidate = path.join(parsed.dir, `${parsed.name} - ${String(counter).padStart(2, "0")}${parsed.ext}`);
    if (!fs.existsSync(candidate)) return candidate;
    counter += 1;
  }
}

function findSoffice() {
  const candidates = [
    "C:\\Program Files\\LibreOffice\\program\\soffice.exe",
    "C:\\Program Files (x86)\\LibreOffice\\program\\soffice.exe",
    "C:\\Program Files\\OpenOffice 4\\program\\soffice.exe",
    "C:\\Program Files (x86)\\OpenOffice 4\\program\\soffice.exe"
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || "soffice";
}

function officePdfFiltersFor(source) {
  const ext = path.extname(source).toLowerCase();
  if ([".odt", ".doc", ".docx", ".rtf"].includes(ext)) return ["pdf:writer_pdf_Export", "pdf"];
  if ([".ods", ".xls", ".xlsx"].includes(ext)) return ["pdf:calc_pdf_Export", "pdf"];
  if ([".odp", ".ppt", ".pptx"].includes(ext)) return ["pdf:impress_pdf_Export", "pdf"];
  return ["pdf"];
}

function officeConversionError(source, outputDir, soffice, attempts) {
  const lines = [`Falha ao converter em PDF: ${source}`, `Pasta de saída: ${outputDir}`, `OpenOffice/LibreOffice: ${soffice}`];
  attempts.forEach((attempt, index) => {
    const status = attempt.status === null || attempt.status === undefined ? "sem código" : attempt.status;
    const signal = attempt.signal ? `, sinal ${attempt.signal}` : "";
    const timedOut = attempt.error && attempt.error.code === "ETIMEDOUT" ? " (tempo excedido)" : "";
    lines.push(`Tentativa ${index + 1} (${attempt.filter}): status ${status}${signal}${timedOut}`);
    if (attempt.error) lines.push(`Erro: ${attempt.error.message}`);
    lines.push(`stdout: ${(attempt.stdout || "").trim() || "sem saída"}`);
    lines.push(`stderr: ${(attempt.stderr || "").trim() || "sem saída"}`);
  });
  lines.push("Dica: feche janelas abertas do OpenOffice/LibreOffice e tente novamente se houver tempo excedido.");
  return lines.join("\n");
}

const UNO_EXPORT_PDF_SCRIPT = `
# -*- coding: utf-8 -*-
import sys, time, uno
from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException

def prop(name, value):
    item = PropertyValue()
    item.Name = name
    item.Value = value
    return item

source = sys.argv[1]
output = sys.argv[2]
filter_name = sys.argv[3]
port = sys.argv[4]
local_ctx = uno.getComponentContext()
resolver = local_ctx.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local_ctx)
ctx = None
last_error = None
deadline = time.time() + 60
while time.time() < deadline:
    try:
        ctx = resolver.resolve("uno:socket,host=127.0.0.1,port=%s;urp;StarOffice.ComponentContext" % port)
        break
    except NoConnectException as error:
        last_error = error
        time.sleep(0.5)
if ctx is None:
    raise Exception("Não conectou ao OpenOffice/LibreOffice UNO: %s" % last_error)
desktop = ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
document = desktop.loadComponentFromURL(uno.systemPathToFileUrl(source), "_blank", 0, (prop("Hidden", True), prop("ReadOnly", True),))
if document is None:
    raise Exception("OpenOffice/LibreOffice não abriu o documento")
document.storeToURL(uno.systemPathToFileUrl(output), (prop("FilterName", filter_name),))
try:
    document.close(True)
except Exception:
    document.dispose()
`;

function officeProgramDir(soffice) {
  return fs.existsSync(soffice) ? path.dirname(soffice) : "";
}

function findOfficePython(soffice) {
  const programDir = officeProgramDir(soffice);
  if (!programDir) return "";
  const candidates = [
    path.join(programDir, "python.exe"),
    path.join(programDir, "python-core-2.7.18", "bin", "python.exe")
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || "";
}

function officeUnoFilterFor(source) {
  const ext = path.extname(source).toLowerCase();
  if ([".ods", ".xls", ".xlsx"].includes(ext)) return "calc_pdf_Export";
  if ([".odp", ".ppt", ".pptx"].includes(ext)) return "impress_pdf_Export";
  return "writer_pdf_Export";
}

function officeEnv(programDir) {
  const env = { ...process.env };
  if (!programDir) return env;
  env.PATH = `${programDir};${env.PATH || ""}`;
  env.PYTHONPATH = programDir;
  const bootstrap = path.join(programDir, "fundamental.ini");
  if (fs.existsSync(bootstrap)) env.URE_BOOTSTRAP = `vnd.sun.star.pathname:${bootstrap.replace(/\\/g, "/")}`;
  return env;
}

function killProcessTree(pid) {
  if (!pid || process.platform !== "win32") return;
  childProcess.spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
    encoding: "utf8",
    timeout: 10000,
    windowsHide: true
  });
}

function killOfficeProcessesForProfile(profile) {
  if (process.platform !== "win32") return;
  const marker = path.basename(profile).replace(/'/g, "''");
  const script = [
    `$marker = '${marker}'`,
    "Get-CimInstance Win32_Process | Where-Object { ($_.Name -like 'soffice*' -or $_.Name -like 'openoffice*') -and $_.CommandLine -like \"*$marker*\" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
  ].join("; ");
  childProcess.spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], {
    encoding: "utf8",
    timeout: 10000,
    windowsHide: true
  });
}

function removeOfficeProfile(profile) {
  killOfficeProcessesForProfile(profile);
  try {
    fs.rmSync(profile, { recursive: true, force: true });
  } catch (_) {
    // A timed-out OpenOffice child can keep a log locked briefly. Temp cleanup is best-effort.
  }
}

function convertFileToPdfWithUno(sourcePath, pdf, soffice, profile) {
  const python = findOfficePython(soffice);
  if (!python) return null;
  const programDir = officeProgramDir(soffice);
  const env = officeEnv(programDir);
  const scriptPath = path.join(profile, "pdfutils_export_pdf.py");
  fs.writeFileSync(scriptPath, UNO_EXPORT_PDF_SCRIPT, "utf8");
  const port = String(24000 + Math.floor(Math.random() * 20000));
  const accept = `socket,host=127.0.0.1,port=${port};urp;StarOffice.ComponentContext`;
  const serverArgs = [
    `-env:UserInstallation=${pathToFileURL(profile).href}`,
    "-headless",
    "-invisible",
    "-nodefault",
    "-nofirststartwizard",
    "-norestore",
    "-nolockcheck",
    `-accept=${accept}`
  ];
  const server = childProcess.spawn(soffice, serverArgs, { env, windowsHide: true, stdio: "ignore" });
  server.on("error", () => {});
  const filter = officeUnoFilterFor(sourcePath);
  let result;
  try {
    result = childProcess.spawnSync(python, [scriptPath, sourcePath, pdf, filter, port], {
      env,
      encoding: "utf8",
      timeout: 120000,
      windowsHide: true
    });
  } finally {
    killProcessTree(server.pid);
    killOfficeProcessesForProfile(profile);
  }
  return { filter: `UNO ${filter}`, status: result.status, signal: result.signal, error: result.error, stdout: result.stdout, stderr: result.stderr };
}

function convertFileToPdf(source, outputDir) {
  const sourcePath = path.resolve(source);
  const outputPath = path.resolve(outputDir);
  if (!fs.existsSync(sourcePath)) throw new Error(`Arquivo para conversão não encontrado: ${sourcePath}`);
  fs.mkdirSync(outputPath, { recursive: true });
  const soffice = findSoffice();
  const profile = path.join(os.tmpdir(), `pdfutils_office_${crypto.randomUUID()}`);
  fs.mkdirSync(profile, { recursive: true });
  const pdf = path.join(outputPath, `${path.basename(sourcePath, path.extname(sourcePath))}.pdf`);
  const attempts = [];
  try {
    const unoResult = convertFileToPdfWithUno(sourcePath, pdf, soffice, profile);
    if (unoResult) {
      attempts.push(unoResult);
      if (fs.existsSync(pdf)) return pdf;
      if (unoResult.error && unoResult.error.code === "ETIMEDOUT") {
        throw new Error(officeConversionError(sourcePath, outputPath, soffice, attempts));
      }
    }
    for (const filter of officePdfFiltersFor(sourcePath)) {
      const args = [
        `-env:UserInstallation=${pathToFileURL(profile).href}`,
        "--headless",
        "--invisible",
        "--nodefault",
        "--nofirststartwizard",
        "--norestore",
        "--nolockcheck",
        "--convert-to",
        filter,
        "--outdir",
        outputPath,
        sourcePath
      ];
      const result = childProcess.spawnSync(soffice, args, { encoding: "utf8", timeout: 120000, windowsHide: true });
      attempts.push({ filter: `convert-to ${filter}`, status: result.status, signal: result.signal, error: result.error, stdout: result.stdout, stderr: result.stderr });
      if (fs.existsSync(pdf)) return pdf;
      if (result.error && result.error.code === "ETIMEDOUT") break;
    }
    throw new Error(officeConversionError(sourcePath, outputPath, soffice, attempts));
  } finally {
    removeOfficeProfile(profile);
  }
}

function jpegExifOrientation(bytes) {
  if (!bytes || bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return 1;
  let offset = 2;
  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) return 1;
    const marker = bytes[offset + 1];
    offset += 2;
    if (marker === 0xda || marker === 0xd9) return 1;
    if (marker >= 0xd0 && marker <= 0xd7) continue;
    if (offset + 2 > bytes.length) return 1;
    const length = bytes.readUInt16BE(offset);
    offset += 2;
    const segmentStart = offset;
    const segmentEnd = segmentStart + length - 2;
    if (segmentEnd > bytes.length || length < 2) return 1;
    if (marker === 0xe1 && segmentEnd - segmentStart >= 14 && bytes.toString("ascii", segmentStart, segmentStart + 6) === "Exif\0\0") {
      const tiff = segmentStart + 6;
      const littleEndian = bytes.toString("ascii", tiff, tiff + 2) === "II";
      const bigEndian = bytes.toString("ascii", tiff, tiff + 2) === "MM";
      if (!littleEndian && !bigEndian) return 1;
      const read16 = (pos) => (littleEndian ? bytes.readUInt16LE(pos) : bytes.readUInt16BE(pos));
      const read32 = (pos) => (littleEndian ? bytes.readUInt32LE(pos) : bytes.readUInt32BE(pos));
      if (read16(tiff + 2) !== 42) return 1;
      const ifd0 = tiff + read32(tiff + 4);
      if (ifd0 + 2 > segmentEnd) return 1;
      const entries = read16(ifd0);
      for (let index = 0; index < entries; index += 1) {
        const entry = ifd0 + 2 + index * 12;
        if (entry + 12 > segmentEnd) break;
        const tag = read16(entry);
        if (tag !== 0x0112) continue;
        const type = read16(entry + 2);
        const count = read32(entry + 4);
        if (type !== 3 || count < 1) return 1;
        return read16(entry + 8);
      }
      return 1;
    }
    offset = segmentEnd;
  }
  return 1;
}

function imageDrawPlan(image, orientation) {
  const size = typeof image.size === "function" ? image.size() : image;
  const width = Number(size.width);
  const height = Number(size.height);
  if (orientation === 3) return { page: [width, height], draw: { x: width, y: height, width, height, rotate: degrees(180) } };
  if (orientation === 6) return { page: [height, width], draw: { x: height, y: 0, width, height, rotate: degrees(90) } };
  if (orientation === 8) return { page: [height, width], draw: { x: 0, y: width, width, height, rotate: degrees(270) } };
  return { page: [width, height], draw: { x: 0, y: 0, width, height } };
}

async function imageToPdf(source, outputDir) {
  const ext = path.extname(source).toLowerCase();
  const bytes = fs.readFileSync(source);
  const imageBytes = new Uint8Array(bytes);
  const pdf = await PDFDocument.create();
  let image;
  if ([".jpg", ".jpeg"].includes(ext)) image = await pdf.embedJpg(imageBytes);
  else if (ext === ".png") image = await pdf.embedPng(imageBytes);
  else return convertFileToPdf(source, outputDir);
  const orientation = [".jpg", ".jpeg"].includes(ext) ? jpegExifOrientation(bytes) : 1;
  const plan = imageDrawPlan(image, orientation);
  const page = pdf.addPage([Number(plan.page[0]), Number(plan.page[1])]);
  page.drawImage(image, plan.draw);
  const output = path.join(outputDir, `${path.basename(source, ext)}.pdf`);
  fs.writeFileSync(output, await pdf.save());
  return output;
}

async function convertSourceToPdf(source, outputDir) {
  const ext = path.extname(source).toLowerCase();
  if (ext === ".pdf") return source;
  if ([".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff"].includes(ext)) return imageToPdf(source, outputDir);
  return convertFileToPdf(source, outputDir);
}

async function mergeFilesToPdf(data, onProgress) {
  const sourcePaths = Array.isArray(data?.sourcePaths)
    ? data.sourcePaths.map((source) => path.resolve(String(source || "").trim())).filter(Boolean)
    : [];
  if (sourcePaths.length < 2) throw new Error("Adicione pelo menos dois arquivos para juntar.");
  for (const source of sourcePaths) {
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
      throw new Error(`Arquivo não encontrado: ${source}`);
    }
  }
  if (!String(data?.outputPath || "").trim()) throw new Error("Escolha o nome do PDF final.");
  const output = path.resolve(ensurePdfExtension(data.outputPath));
  if (sourcePaths.some((source) => path.normalize(source).toLowerCase() === path.normalize(output).toLowerCase())) {
    throw new Error("O PDF final deve ter um nome diferente dos arquivos de origem.");
  }

  const tempDir = data.tempDir
    ? path.resolve(data.tempDir)
    : fs.mkdtempSync(path.join(os.tmpdir(), "pdfutils_merge_"));
  fs.mkdirSync(tempDir, { recursive: true });
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const merged = await PDFDocument.create();
  let pageCount = 0;

  try {
    onProgress?.("Preparando arquivos...", 4);
    for (let index = 0; index < sourcePaths.length; index += 1) {
      const source = sourcePaths[index];
      const itemNumber = index + 1;
      const itemProgress = 8 + Math.round((index / sourcePaths.length) * 76);
      onProgress?.(`Convertendo ${itemNumber} de ${sourcePaths.length}: ${path.basename(source)}`, itemProgress);
      const itemDir = path.join(tempDir, `item_${String(itemNumber).padStart(3, "0")}`);
      fs.mkdirSync(itemDir, { recursive: true });

      let sourcePdf;
      try {
        sourcePdf = await convertSourceToPdf(source, itemDir);
      } catch (error) {
        throw new Error(`Não foi possível converter "${path.basename(source)}" em PDF: ${error.message}`);
      }

      let document;
      try {
        document = await PDFDocument.load(fs.readFileSync(sourcePdf));
      } catch (error) {
        throw new Error(`Não foi possível abrir "${path.basename(source)}" como PDF: ${error.message}`);
      }
      const sourcePageCount = document.getPageCount();
      if (!sourcePageCount) throw new Error(`O arquivo "${path.basename(source)}" não possui páginas.`);
      const copiedPages = await merged.copyPages(document, document.getPageIndices());
      copiedPages.forEach((page) => merged.addPage(page));
      pageCount += copiedPages.length;
    }

    onProgress?.("Gerando o PDF final...", 90);
    fs.writeFileSync(output, await merged.save());
    const validation = await pdfFileIsViewable(output);
    if (!validation.ok) {
      fs.rmSync(output, { force: true });
      throw new Error(`O PDF final não ficou visualizável: ${validation.reason}`);
    }
    onProgress?.("PDF final criado com sucesso.", 100);
    return {
      output,
      sourceCount: sourcePaths.length,
      pageCount
    };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function executableFromPath(name) {
  const pathValue = process.env.PATH || process.env.Path || "";
  for (const folder of pathValue.split(path.delimiter)) {
    if (!folder) continue;
    const candidate = path.join(folder, name);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function findGhostscript() {
  for (const executableName of ["gswin64c.exe", "gswin32c.exe"]) {
    const candidate = executableFromPath(executableName);
    if (candidate) return candidate;
  }

  const roots = ["C:\\Program Files\\gs", "C:\\Program Files (x86)\\gs"];
  for (const root of roots) {
    if (!fs.existsSync(root)) continue;
    for (const version of fs.readdirSync(root).sort().reverse()) {
      for (const executableName of ["gswin64c.exe", "gswin32c.exe"]) {
        const candidate = path.join(root, version, "bin", executableName);
        if (fs.existsSync(candidate)) return candidate;
      }
    }
  }
  return null;
}

function ghostscriptVersion(executable = findGhostscript()) {
  if (!executable) return "";
  const result = childProcess.spawnSync(executable, ["--version"], {
    encoding: "utf8",
    timeout: 10000,
    windowsHide: true
  });
  if (result.status !== 0) return "";
  return String(result.stdout || "").trim().split(/\s+/)[0] || "";
}

const PDF_A_CANDIDATES = [
  { version: 1, label: "PDF/A-1b" },
  { version: 2, label: "PDF/A-2b" },
  { version: 3, label: "PDF/A-3b" }
];

function pdfFileHasHeader(filePath) {
  if (!fs.existsSync(filePath)) return false;
  const stat = fs.statSync(filePath);
  if (stat.size < 8) return false;
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.alloc(8);
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    return buffer.toString("ascii").startsWith("%PDF");
  } finally {
    fs.closeSync(fd);
  }
}

async function pdfFileIsViewable(filePath, gs = findGhostscript()) {
  if (!pdfFileHasHeader(filePath)) return { ok: false, reason: "arquivo ausente, vazio ou sem cabeçalho PDF" };
  try {
    const document = await PDFDocument.load(fs.readFileSync(filePath), { ignoreEncryption: true });
    if (document.getPageCount() < 1) return { ok: false, reason: "PDF sem páginas" };
  } catch (error) {
    return { ok: false, reason: `pdf-lib não conseguiu abrir: ${error.message}` };
  }
  if (gs) {
    const result = childProcess.spawnSync(gs, ["-dBATCH", "-dNOPAUSE", "-sDEVICE=nullpage", filePath], {
      encoding: "utf8",
      timeout: 120000,
      windowsHide: true
    });
    if (result.status !== 0) {
      return { ok: false, reason: `Ghostscript não conseguiu renderizar: ${ghostscriptMessage(result) || `status ${result.status ?? "sem código"}`}` };
    }
  }
  return { ok: true, reason: "" };
}

function ghostscriptMessage(result) {
  return [result.stderr, result.stdout, result.error?.message].filter(Boolean).join("\n").trim();
}

function plural(count, singular, pluralText) {
  return `${count} ${count === 1 ? singular : pluralText}`;
}

function summarizeGhostscriptMessage(message) {
  const lines = String(message || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) return "";
  const unmatched = new Set();
  let nonPrintingAnnotations = 0;
  let interpolateImages = 0;
  let clampedCoordinates = 0;
  let repairedErrors = false;
  for (const line of lines) {
    if (/Annotation set to non-printing/i.test(line)) nonPrintingAnnotations += 1;
    else if (/PDFA doesn't allow images with Interpolate true/i.test(line)) interpolateImages += 1;
    else if (/clamping to valid range/i.test(line)) clampedCoordinates += 1;
    else if (/errors were encountered|errors that were repaired or ignored|does not conform to Adobe/i.test(line)) repairedErrors = true;
    else if (!/^(\*+|GPL Ghostscript|The file was produced by:|>>>>|Please notify the author)/i.test(line)) unmatched.add(line);
  }
  const summary = [];
  if (nonPrintingAnnotations) summary.push(`removeu ${plural(nonPrintingAnnotations, "anotação não imprimível", "anotações não imprimíveis")} que não são permitidas em PDF/A`);
  if (interpolateImages) summary.push(`ajustou ${plural(interpolateImages, "imagem com Interpolate=true", "imagens com Interpolate=true")}, recurso não permitido em PDF/A`);
  if (clampedCoordinates) summary.push(`corrigiu ${plural(clampedCoordinates, "coordenada fora do limite", "coordenadas fora do limite")}`);
  if (repairedErrors) summary.push("reparou ou ignorou erros internos do PDF de origem");
  if (unmatched.size) summary.push(`registrou ${plural(unmatched.size, "outro aviso", "outros avisos")} durante a conversão`);
  return summary.length ? summary.map((item) => `- ${item}`).join("\n") : `- ${plural(lines.length, "aviso do Ghostscript", "avisos do Ghostscript")} durante a conversão`;
}

function pdfALogPath(output) {
  const parsed = path.parse(output);
  return path.join(parsed.dir, `${parsed.name} - log PDF-A.txt`);
}

function writePdfALog(output, selectedLabel, attempts) {
  if (!attempts.length) return "";
  const logPath = pdfALogPath(output);
  const content = [
    `Gerado em: ${new Date().toISOString()}`,
    `PDF/A final escolhido: ${selectedLabel || "nenhum"}`,
    "",
    "Candidatos e mensagens:",
    "",
    attempts.join("\n\n")
  ].join("\n");
  fs.writeFileSync(logPath, content, "utf8");
  return logPath;
}

function ghostscriptPdfAArgs(source, output, version) {
  return [
    `-dPDFA=${version}`,
    "-dBATCH",
    "-dNOPAUSE",
    "-dNOOUTERSAVE",
    "-dAutoRotatePages=/None",
    "-sDEVICE=pdfwrite",
    "-dPDFACompatibilityPolicy=1",
    `-sOutputFile=${output}`,
    source
  ];
}

function pdfACandidatePath(output, label) {
  const parsed = path.parse(output);
  return path.join(parsed.dir, `${parsed.name} - ${label.replace("/", "-")}${parsed.ext}`);
}

function removeGeneratedPdfACandidates(generated) {
  for (const candidate of generated) fs.rmSync(candidate, { force: true });
}

async function stripPdfAnnotationsForPdfA(source) {
  const output = path.join(path.dirname(source), `sem_anotacoes_${crypto.randomUUID()}.pdf`);
  try {
    const pdf = await PDFDocument.load(fs.readFileSync(source), { ignoreEncryption: true });
    let removed = 0;
    for (const page of pdf.getPages()) {
      const annots = page.node.lookupMaybe(PDFName.of("Annots"), PDFArray);
      if (annots) removed += annots.size();
      page.node.delete(PDFName.of("Annots"));
    }
    if (!removed) return { source, temp: "", removed: 0, warning: "" };
    fs.writeFileSync(output, await pdf.save());
    return { source: output, temp: output, removed, warning: "" };
  } catch (error) {
    return { source, temp: "", removed: 0, warning: `Pré-processamento: não foi possível remover anotações do PDF antes do PDF/A (${error.message}).` };
  }
}

async function convertPdfToPdfAIfPossible(source, output) {
  fs.rmSync(pdfALogPath(output), { force: true });
  const gs = findGhostscript();
  if (!gs) {
    fs.copyFileSync(source, output);
    return { pdfa: false, warning: "Ghostscript não encontrado. O PDF final foi gerado sem normalização PDF/A." };
  }
  const sanitized = await stripPdfAnnotationsForPdfA(source);
  const sourceForPdfA = sanitized.source;
  const attempts = [];
  if (sanitized.removed) attempts.push(`Pré-processamento: removidas ${plural(sanitized.removed, "anotação de PDF", "anotações de PDF")} antes da conversão PDF/A.`);
  if (sanitized.warning) attempts.push(sanitized.warning);
  const generated = [];
  const viewable = [];
  for (const candidate of PDF_A_CANDIDATES) {
    const { version, label } = candidate;
    const candidateOutput = pdfACandidatePath(output, label);
    const tempOutput = path.join(path.dirname(output), `pdfa_${version}_${crypto.randomUUID()}.pdf`);
    const result = childProcess.spawnSync(gs, ghostscriptPdfAArgs(sourceForPdfA, tempOutput, version), {
      encoding: "utf8",
      timeout: 180000,
      windowsHide: true
    });
    const message = ghostscriptMessage(result);
    let validation = { ok: false, reason: "Ghostscript não gerou um arquivo PDF" };
    if (pdfFileHasHeader(tempOutput)) {
      fs.copyFileSync(tempOutput, candidateOutput);
      generated.push(candidateOutput);
      validation = await pdfFileIsViewable(candidateOutput, gs);
      if (validation.ok) viewable.push({ ...candidate, output: candidateOutput, message });
    }
    attempts.push(`${label}: ${validation.ok ? "visualizável" : `não visualizável (${validation.reason})`}${message ? `\n${message}` : ""}`);
    fs.rmSync(tempOutput, { force: true });
  }
  const chosen = viewable[0];
  if (chosen) {
    fs.copyFileSync(chosen.output, output);
    removeGeneratedPdfACandidates(generated);
    fs.rmSync(pdfALogPath(output), { force: true });
    if (sanitized.temp) fs.rmSync(sanitized.temp, { force: true });
    const summary = summarizeGhostscriptMessage(chosen.message);
    const warningParts = [];
    if (chosen.label !== "PDF/A-1b") {
      warningParts.push(`O app gerou candidatos em PDF/A-1b, PDF/A-2b e PDF/A-3b e manteve como final o mais rígido visualizável: ${chosen.label}.`);
    }
    if (summary) warningParts.push(`O Ghostscript fez ajustes no PDF escolhido:\n${summary}`);
    return { pdfa: true, warning: warningParts.join("\n\n"), candidates: [], selectedPdfA: chosen.label, pdfaLog: "" };
  }
  fs.copyFileSync(sourceForPdfA, output);
  removeGeneratedPdfACandidates(generated);
  if (sanitized.temp) fs.rmSync(sanitized.temp, { force: true });
  const logPath = writePdfALog(output, "", attempts);
  return {
    pdfa: false,
    candidates: [],
    pdfaLog: logPath,
    warning: `Nenhum candidato PDF/A ficou visualizável. O PDF final foi gerado como PDF comum.${logPath ? `\n\nLog completo: ${logPath}` : ""}`
  };
}

async function convertAnyFileToPdfA(data, onProgress) {
  if (!String(data.sourcePath || "").trim()) throw new Error("Selecione um arquivo válido para converter em PDF/A.");
  const source = path.resolve(data.sourcePath);
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) throw new Error("Selecione um arquivo válido para converter em PDF/A.");
  const gs = findGhostscript();
  if (!gs) throw new Error("Ghostscript não encontrado. Instale o Ghostscript para converter em PDF/A.");
  if (!String(data.outputPath || "").trim()) throw new Error("Escolha o nome do PDF/A de saída.");
  const output = path.resolve(ensurePdfExtension(data.outputPath));
  if (path.normalize(output).toLowerCase() === path.normalize(source).toLowerCase()) {
    throw new Error("Escolha um arquivo de saída diferente do arquivo original.");
  }
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const tempDir = data.tempDir
    ? path.resolve(data.tempDir)
    : fs.mkdtempSync(path.join(os.tmpdir(), "pdfutils_pdfa_"));
  fs.mkdirSync(tempDir, { recursive: true });
  try {
    onProgress?.("Preparando arquivo...");
    let sourcePdf;
    try {
      sourcePdf = await convertSourceToPdf(source, tempDir);
    } catch (error) {
      throw new Error(`Falha ao preparar o arquivo como PDF: ${error.message}`);
    }
    onProgress?.("Convertendo para PDF/A com Ghostscript...");
    const result = await convertPdfToPdfAIfPossible(sourcePdf, output);
    if (!result.pdfa) throw new Error(result.warning || "O Ghostscript não conseguiu gerar um PDF/A visualizável.");
    onProgress?.(`PDF/A criado: ${output}`);
    return { output, ...result };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function parsePdfAMetadata(buffer) {
  const text = buffer.toString("latin1");
  const part =
    text.match(/<pdfaid:part>\s*(\d+)\s*<\/pdfaid:part>/i)?.[1]
    || text.match(/pdfaid:part=["']?(\d+)/i)?.[1]
    || text.match(/pdfaid_part["'\s:=]+(\d+)/i)?.[1]
    || "";
  const conformance =
    text.match(/<pdfaid:conformance>\s*([A-Z])\s*<\/pdfaid:conformance>/i)?.[1]
    || text.match(/pdfaid:conformance=["']?([A-Z])/i)?.[1]
    || text.match(/pdfaid_conformance["'\s:=]+([A-Z])/i)?.[1]
    || "";
  return {
    part,
    conformance: conformance ? conformance.toUpperCase() : "",
    rawFound: /pdfaid:part|pdfaid_part|pdfaSchema|pdfaid:conformance/i.test(text)
  };
}

async function validatePdfA(data) {
  if (!String(data.sourcePath || "").trim()) throw new Error("Selecione um PDF para validar.");
  const source = path.resolve(data.sourcePath);
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) throw new Error("Selecione um PDF válido para validar.");
  if (path.extname(source).toLowerCase() !== ".pdf") throw new Error("A validação PDF/A aceita apenas arquivos PDF.");
  if (!pdfFileHasHeader(source)) return { isPdfA: false, validPdf: false, level: "", details: "O arquivo não possui cabeçalho PDF." };

  const buffer = fs.readFileSync(source);
  let pages = 0;
  try {
    const pdf = await PDFDocument.load(buffer, { ignoreEncryption: true });
    pages = pdf.getPageCount();
  } catch (error) {
    return { isPdfA: false, validPdf: false, level: "", details: `Não foi possível abrir o PDF: ${error.message}` };
  }

  const metadata = parsePdfAMetadata(buffer);
  const viewable = await pdfFileIsViewable(source);
  const isPdfA = Boolean(metadata.part && metadata.conformance && viewable.ok);
  const level = isPdfA ? `PDF/A-${metadata.part}${metadata.conformance.toLowerCase()}` : "";
  const details = isPdfA
    ? `Documento identificado como ${level}. Páginas: ${pages}.`
    : metadata.rawFound
      ? `Foram encontrados metadados PDF/A incompletos ou inconsistentes. ${viewable.ok ? "" : viewable.reason}`.trim()
      : `Não foram encontrados metadados PDF/A no documento. Páginas: ${pages}.`;
  return { isPdfA, validPdf: viewable.ok, level, pages, details, metadata };
}

async function preparePdfAForSigning(data, onProgress) {
  const source = path.resolve(data.sourcePath || "");
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) throw new Error("Selecione um arquivo válido para assinar.");
  const tempDir = data.tempDir
    ? path.resolve(data.tempDir)
    : fs.mkdtempSync(path.join(os.tmpdir(), "pdfutils_sign_"));
  fs.mkdirSync(tempDir, { recursive: true });
  const cleanup = () => fs.rmSync(tempDir, { recursive: true, force: true });
  try {
    onProgress?.("Verificando PDF/A...");
    if (path.extname(source).toLowerCase() === ".pdf") {
      const validation = await validatePdfA({ sourcePath: source });
      if (validation.isPdfA) {
        return { preparedPath: source, converted: false, validation, tempDir, cleanup };
      }
    }
    const outputName = safeFilename(data.outputBaseName || path.basename(source, path.extname(source)), "documento-assinavel");
    const output = path.join(tempDir, `${outputName} - PDF-A.pdf`);
    onProgress?.("Convertendo para PDF/A antes da assinatura...");
    const result = await convertAnyFileToPdfA({
      sourcePath: source,
      outputPath: output,
      tempDir: path.join(tempDir, "conversion")
    }, onProgress);
    const validation = await validatePdfA({ sourcePath: result.output });
    return { preparedPath: result.output, converted: true, conversion: result, validation, tempDir, cleanup };
  } catch (error) {
    cleanup();
    throw error;
  }
}

function readPdfBase64(filePath) {
  return fs.readFileSync(filePath).toString("base64");
}

function writePdfBase64(filePath, base64) {
  const output = path.resolve(ensurePdfExtension(filePath));
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, Buffer.from(String(base64 || ""), "base64"));
  return output;
}

module.exports = {
  safeFilename,
  ensurePdfExtension,
  uniquePath,
  findGhostscript,
  findSoffice,
  convertFileToPdf,
  convertSourceToPdf,
  mergeFilesToPdf,
  convertPdfToPdfAIfPossible,
  convertAnyFileToPdfA,
  validatePdfA,
  preparePdfAForSigning,
  readPdfBase64,
  writePdfBase64,
  parsePdfAMetadata,
  ghostscriptVersion
};
