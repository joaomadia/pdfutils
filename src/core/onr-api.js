const DEFAULT_ONR_BASE_URL = "https://assinador-web.onr.org.br";
const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_SIGNATURE_TIMEOUT_MS = 20 * 60 * 1000;

function normalizeBaseUrl(value) {
  const baseUrl = String(value || DEFAULT_ONR_BASE_URL).trim().replace(/\/+$/, "");
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error("A URL da API do Assinador ONR é inválida.");
  }
  if (parsed.protocol !== "https:") throw new Error("A URL da API do Assinador ONR deve usar HTTPS.");
  return baseUrl;
}

function parseExtraHeaders(config = {}) {
  const text = String(config.onrExtraHeadersJson || "{}").trim() || "{}";
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`Os headers extras da ONR não são um JSON válido: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Headers extras da ONR devem ser um objeto JSON.");
  }
  return parsed;
}

function responseMessage(data, fallback = "") {
  if (!data) return fallback;
  if (typeof data === "string") return data.trim() || fallback;
  const code = data.code || data.Code || "";
  const message = data.detail || data.Detail || data.message || data.Message || data.title || data.Title || "";
  const errors = data.errors || data.Errors || data.details || data.Details;
  const details = errors && typeof errors === "object"
    ? Object.entries(errors).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`).join("; ")
    : "";
  return [code, message, details].filter(Boolean).join(" - ") || fallback;
}

function createHttpError(status, data, statusText = "") {
  const detail = responseMessage(data, statusText);
  let message;
  if (status === 401) {
    message = "ONR respondeu HTTP 401: a API Key está ausente ou inválida.";
  } else if (status === 403) {
    message = "ONR respondeu HTTP 403: a API Key não possui permissão para criar sessões de assinatura.";
  } else if (status === 422) {
    message = `ONR recusou a operação: ${detail || "erro de validação"}`;
  } else {
    message = `ONR respondeu HTTP ${status}: ${detail || statusText || "erro não informado"}`;
  }
  const error = new Error(message);
  error.status = status;
  error.response = data;
  return error;
}

function apiHeaders(config, options = {}) {
  const apiKey = String(config.onrApiKey || "").trim();
  if (!apiKey) throw new Error("Configure a API Key (X-Api-Key) da ONR nas Configurações antes de assinar.");
  const headers = {
    Accept: options.accept || "application/json, text/plain, */*",
    "Accept-Language": "pt-BR",
    ...parseExtraHeaders(config),
    "X-Api-Key": apiKey
  };
  if (options.json) headers["Content-Type"] = "application/json";
  return headers;
}

async function requestJson(config, endpoint, options = {}) {
  const fetchImpl = options.fetchImpl || global.fetch;
  if (typeof fetchImpl !== "function") throw new Error("Cliente HTTP indisponivel para acessar o Assinador ONR.");
  const path = String(endpoint || "").startsWith("/") ? endpoint : `/${endpoint}`;

  let response;
  try {
    response = await fetchImpl(`${normalizeBaseUrl(config.onrBaseUrl)}${path}`, {
      method: options.method || "GET",
      headers: apiHeaders(config, { json: options.body !== undefined }),
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    const friendly = new Error("Não foi possível estabelecer conexão com o Assinador ONR.");
    friendly.cause = error;
    throw friendly;
  }

  const text = await response.text();
  let data = text;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    // Some API errors are returned as plain text.
  }
  if (!response.ok) throw createHttpError(response.status, data, response.statusText);
  return data;
}

function buildSignatureSessionRequest({ returnUrl, contentBase64, fileName }) {
  if (!contentBase64) throw new Error("Documento não informado para assinatura ONR.");
  return {
    returnUrl,
    enableBackgroundProcessing: false,
    disableDownloads: true,
    documents: [
      {
        file: {
          content: contentBase64,
          name: String(fileName || "documento.pdf").trim() || "documento.pdf",
          mimeType: "application/pdf",
          contentType: "application/pdf"
        },
        signatureType: "Pdf"
      }
    ],
    certificateRequirements: [
      {
        type: "CryptoDevice"
      }
    ]
  };
}

function buildPrepareSignatureRequest({ contentBase64, fileName, certificateContent }) {
  if (!contentBase64) throw new Error("Documento não informado para assinatura ONR.");
  if (!certificateContent) throw new Error("Certificado digital não informado para assinatura ONR.");
  return {
    file: {
      content: contentBase64,
      name: String(fileName || "documento.pdf").trim() || "documento.pdf",
      mimeType: "application/pdf",
      contentType: "application/pdf"
    },
    certificate: {
      content: certificateContent
    },
    signatureType: "Pdf",
    pdfSignatureOptions: {
      convertToPdfA: false
    }
  };
}

function digestAlgorithmForWebPki(value) {
  const normalized = String(value || "SHA256").trim().toUpperCase().replace(/[_-]/g, "");
  const algorithms = {
    MD5: "MD5",
    SHA1: "SHA-1",
    SHA256: "SHA-256",
    SHA384: "SHA-384",
    SHA512: "SHA-512",
    SHA3256: "SHA3-256"
  };
  return algorithms[normalized] || String(value || "SHA-256").trim();
}

function signatureHashParameters(response) {
  const hashModel = response?.toSignHash || {};
  const toSign = response?.toSign || {};
  let hash = String(hashModel.value || toSign.hash || "").trim();
  if (!hash && hashModel.hexValue) {
    const hex = String(hashModel.hexValue).replace(/\s+/g, "");
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
      throw new Error("A ONR retornou um hash inválido para assinatura.");
    }
    hash = Buffer.from(hex, "hex").toString("base64");
  }
  if (!hash) throw new Error("A ONR não retornou o hash do documento para assinatura.");

  const digestAlgorithm = digestAlgorithmForWebPki(
    hashModel.algorithm || toSign.signatureAlgorithm?.digestAlgorithm || "SHA256"
  );
  return {
    state: String(response?.state || "").trim(),
    hash,
    digestAlgorithm
  };
}

function prepareFailureMessage(failure) {
  const labels = {
    PdfAlreadySigned: "o PDF já está assinado",
    CorruptedPdf: "o PDF esta corrompido",
    CertificateValidationFailed: "o certificado selecionado não foi aceito",
    PasswordProtectedPdf: "o PDF esta protegido por senha",
    PdfAConversionFailed: "não foi possível converter o PDF para PDF/A",
    PdfANonCompliant: "o documento não está em conformidade com PDF/A"
  };
  const key = String(failure ?? "").trim();
  return labels[key] || key || "motivo não informado";
}

async function prepareSignature(config, payload, options = {}) {
  const response = await requestJson(config, "/api/signature", {
    method: "POST",
    body: buildPrepareSignatureRequest(payload),
    fetchImpl: options.fetchImpl,
    signal: options.signal
  });
  if (response?.success === false) {
    throw new Error(`A ONR recusou a preparação da assinatura: ${prepareFailureMessage(response.failure)}.`);
  }
  if (!String(response?.state || "").trim()) {
    throw new Error("A ONR não retornou o estado necessário para concluir a assinatura.");
  }
  signatureHashParameters(response);
  return response;
}

async function completeSignature(config, payload, options = {}) {
  const state = String(payload?.state || "").trim();
  const signature = String(payload?.signature || "").trim();
  if (!state) throw new Error("Estado da assinatura ONR não informado.");
  if (!signature) throw new Error("O componente Web PKI não retornou a assinatura digital.");
  return requestJson(config, "/api/signature/completion", {
    method: "POST",
    body: { state, signature },
    fetchImpl: options.fetchImpl,
    signal: options.signal
  });
}

function signedFileFromDocument(document) {
  const file = document?.signedFile || document?.SignedFile;
  return file && typeof file === "object" ? file : null;
}

function documentValidationUrl(documentKey, baseUrl = DEFAULT_ONR_BASE_URL) {
  const key = String(documentKey || "").trim();
  if (!key) return "";
  return `${normalizeBaseUrl(baseUrl)}/pt/docs/${encodeURIComponent(key)}`;
}

function signatureSessionId(response) {
  return String(response?.sessionId || response?.SessionId || response?.signatureSessionId || response?.SignatureSessionId || response?.id || response?.Id || "").trim();
}

function signatureRedirectUrl(response) {
  return String(response?.redirectUrl || response?.RedirectUrl || response?.url || response?.Url || "").trim();
}

function signatureSessionStatus(session) {
  return String(session?.status || session?.Status || "").trim();
}

function firstSignedFile(session) {
  const documents = session?.documents || session?.Documents;
  if (!Array.isArray(documents)) return null;
  for (const document of documents) {
    const file = document?.signedFile || document?.SignedFile;
    if (!file || typeof file !== "object") continue;
    if (file.content || file.Content || file.location || file.Location || file.url || file.Url) {
      return { file, document };
    }
  }
  return null;
}

async function createSignatureSession(config, payload, options = {}) {
  const body = buildSignatureSessionRequest(payload);
  options.onProgress?.("Criando sessão de assinatura no Assinador ONR...");
  const response = await requestJson(config, "/api/signature-sessions", {
    method: "POST",
    body,
    fetchImpl: options.fetchImpl,
    signal: options.signal
  });
  const sessionId = signatureSessionId(response);
  const redirectUrl = signatureRedirectUrl(response);
  if (!sessionId) throw new Error("A ONR não retornou o ID da sessão de assinatura.");
  if (!redirectUrl) throw new Error("A ONR não retornou a URL de assinatura.");

  let parsedRedirectUrl;
  try {
    parsedRedirectUrl = new URL(redirectUrl);
  } catch {
    throw new Error("A ONR retornou uma URL de assinatura inválida.");
  }
  if (parsedRedirectUrl.protocol !== "https:") throw new Error("A ONR retornou uma URL de assinatura insegura.");
  return { sessionId, redirectUrl, response };
}

async function waitForSignatureSession(config, sessionId, options = {}) {
  const timeoutMs = options.timeoutMs || DEFAULT_SIGNATURE_TIMEOUT_MS;
  const intervalMs = options.intervalMs || DEFAULT_POLL_INTERVAL_MS;
  const sleep = options.sleep || ((duration) => new Promise((resolve) => setTimeout(resolve, duration)));
  const deadline = Date.now() + timeoutMs;
  let lastStatus = "";

  while (Date.now() < deadline) {
    const session = await requestJson(config, `/api/signature-sessions/${encodeURIComponent(sessionId)}`, {
      fetchImpl: options.fetchImpl,
      signal: options.signal
    });
    const status = signatureSessionStatus(session);
    if (status !== lastStatus) {
      lastStatus = status;
      options.onStatus?.(status || "Pending", session);
    }
    if (status.toLowerCase() === "completed") return session;

    const failedStatus = status.toLowerCase();
    if (["usercancelled", "user_cancelled", "cancelled", "canceled", "expired", "processingerror"].includes(failedStatus)) {
      const labels = {
        usercancelled: "cancelada pelo usuário",
        user_cancelled: "cancelada pelo usuário",
        cancelled: "cancelada pelo usuário",
        canceled: "cancelada pelo usuário",
        expired: "expirada",
        processingerror: "não processada pela ONR"
      };
      const processingCode = session?.processingErrorCode ? ` Codigo: ${session.processingErrorCode}.` : "";
      throw new Error(`Assinatura ONR ${labels[failedStatus]}.${processingCode}`);
    }
    await sleep(intervalMs);
  }
  throw new Error("Tempo esgotado aguardando a assinatura no portal ONR.");
}

async function downloadSignedFile(config, file, options = {}) {
  const embedded = String(file?.content || file?.Content || "").trim();
  if (embedded) return embedded;

  const location = String(file?.location || file?.Location || file?.url || file?.Url || "").trim();
  if (!location) throw new Error("A ONR não retornou o link do PDF assinado.");
  const baseUrl = new URL(`${normalizeBaseUrl(config.onrBaseUrl)}/`);
  const resolvedUrl = new URL(location, baseUrl);
  const url = resolvedUrl.toString();
  const fetchImpl = options.fetchImpl || global.fetch;
  const headers = resolvedUrl.origin === baseUrl.origin
    ? apiHeaders(config, { accept: "application/pdf, application/octet-stream, */*" })
    : { Accept: "application/pdf, application/octet-stream, */*" };

  let response;
  try {
    response = await fetchImpl(url, {
      headers,
      signal: options.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    const friendly = new Error("Não foi possível baixar o PDF assinado da ONR.");
    friendly.cause = error;
    throw friendly;
  }
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw createHttpError(response.status, text, response.statusText);
  }
  return Buffer.from(await response.arrayBuffer()).toString("base64");
}

module.exports = {
  DEFAULT_ONR_BASE_URL,
  DEFAULT_SIGNATURE_TIMEOUT_MS,
  apiHeaders,
  buildPrepareSignatureRequest,
  buildSignatureSessionRequest,
  completeSignature,
  createHttpError,
  createSignatureSession,
  digestAlgorithmForWebPki,
  documentValidationUrl,
  downloadSignedFile,
  firstSignedFile,
  normalizeBaseUrl,
  parseExtraHeaders,
  prepareSignature,
  requestJson,
  signatureHashParameters,
  signatureRedirectUrl,
  signatureSessionId,
  signatureSessionStatus,
  signedFileFromDocument,
  waitForSignatureSession
};
