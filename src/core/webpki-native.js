const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const WEB_PKI_NOT_FOUND = "Componente Web PKI não encontrado, por favor faça a instalação na aba de configurações e tente novamente.";

const KEY_USAGE_FLAGS = {
  crlSign: 2,
  dataEncipherment: 16,
  decipherOnly: 32768,
  digitalSignature: 128,
  encipherOnly: 1,
  keyAgreement: 8,
  keyCertSign: 4,
  keyEncipherment: 32,
  nonRepudiation: 64
};

const EXTENDED_KEY_USAGE_FLAGS = {
  clientAuth: 1,
  serverAuth: 2,
  codeSigning: 4,
  emailProtection: 8,
  timeStamping: 16,
  ocspSigning: 32,
  ipsecEndSystem: 64,
  ipsecTunnel: 128,
  ipsecUser: 256,
  any: 512
};

function localAppData() {
  return process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
}

function nativeHostCandidates() {
  const base = path.join(localAppData(), "Lacuna Software", "Web PKI");
  return [
    path.join(base, "native-host-chrome.json"),
    path.join(base, "native-host-edge.json"),
    path.join(base, "Lacuna.WebPKI.ChromeWin.exe")
  ];
}

function executableFromManifest(manifestPath) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const target = String(manifest.path || "").trim();
  if (!target) return "";
  return path.isAbsolute(target) ? target : path.resolve(path.dirname(manifestPath), target);
}

function resolveNativeExecutable() {
  for (const candidate of nativeHostCandidates()) {
    try {
      const target = candidate.endsWith(".json") ? executableFromManifest(candidate) : candidate;
      if (target && fs.existsSync(target)) return target;
    } catch (_) {
      // Try the next known install location.
    }
  }
  throw new Error(WEB_PKI_NOT_FOUND);
}

function randomId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function writeNativeMessage(stream, message) {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  const size = Buffer.alloc(4);
  size.writeUInt32LE(payload.length, 0);
  stream.write(Buffer.concat([size, payload]));
}

function parseKeyUsage(value) {
  if (value && typeof value === "object") return value;
  const number = Number(value) || 0;
  return Object.fromEntries(Object.entries(KEY_USAGE_FLAGS).map(([key, flag]) => [key, (number & flag) !== 0]));
}

function parseExtendedKeyUsage(value) {
  if (value && typeof value === "object") return value;
  if (typeof value !== "number") return null;
  return Object.fromEntries(Object.entries(EXTENDED_KEY_USAGE_FLAGS).map(([key, flag]) => [key, (value & flag) !== 0]));
}

function normalizeCertificate(cert) {
  return {
    ...cert,
    keyUsage: parseKeyUsage(cert.keyUsage),
    extendedKeyUsage: parseExtendedKeyUsage(cert.extendedKeyUsage),
    source: "Windows"
  };
}

function nativeErrorFromException(exception, stderr = "") {
  const message = exception?.message || exception?.error || exception || stderr || "Erro no componente Web PKI.";
  const error = new Error(String(message));
  if (exception?.code) error.code = exception.code;
  if (stderr) error.stderr = stderr;
  return error;
}

function isBufferedResponse(result) {
  return !result.success && result.exception?.code === "io_error" && result.streamId && result.streamLength;
}

function commandMessage({ config, command, request, requestId, keepAlive = true }) {
  return {
    requestId,
    license: config?.webPkiLicense || "",
    domain: config?.webPkiDomain || "localhost",
    command,
    request,
    language: "pt-BR",
    keepAlive,
    trace: false,
    pkcs11Modules: [],
    requireLicense: false
  };
}

function commandNeedsVisibleWindow(command) {
  return ["authorizeSignatures", "signData", "signHash", "signPdf"].includes(command);
}

function signatureAuthorizationRequest(certificateThumbprint, signatureCount = 1) {
  return {
    certificateThumbprint,
    signatureCount,
    enableDontAskAgain: false
  };
}

function cancelledError() {
  const error = new Error("Assinatura ONR cancelada pelo usuário.");
  error.name = "AbortError";
  error.code = "user_cancelled";
  return error;
}

function runNativeCommand(config, command, request, options = {}) {
  if (options.signal?.aborted) return Promise.reject(cancelledError());
  const timeoutMs = options.timeoutMs || 300000;
  const executable = resolveNativeExecutable();
  const authorization = options.authorizeSignatures;
  const showWindow = Boolean(authorization) || commandNeedsVisibleWindow(command);
  const signal = options.signal;

  return new Promise((resolve, reject) => {
    const child = spawn(executable, [], {
      cwd: path.dirname(executable),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: !showWindow
    });
    const pending = new Map();
    let stdoutBuffer = Buffer.alloc(0);
    let stderr = "";
    let settled = false;
    let abortHandler = null;

    const timer = setTimeout(() => {
      finish(null, new Error(`Tempo esgotado ao executar ${command} no componente Web PKI.`));
    }, timeoutMs);

    function finish(value, error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (signal && abortHandler) signal.removeEventListener("abort", abortHandler);
      try {
        child.kill();
      } catch (_) {
        // Process may already have ended.
      }
      if (error) reject(error);
      else resolve(value);
    }

    function send(commandName, commandRequest, keepAlive = true) {
      return new Promise((messageResolve, messageReject) => {
        const requestId = randomId();
        pending.set(requestId, { resolve: messageResolve, reject: messageReject });
        writeNativeMessage(child.stdin, commandMessage({
          config,
          command: commandName,
          request: commandRequest,
          requestId,
          keepAlive
        }));
      });
    }

    async function readBuffered(result) {
      let buffer = "";
      let offset = 0;
      while (offset < result.streamLength) {
        const chunkResult = await send("readBufferedResponse", { streamId: result.streamId, offset });
        if (!chunkResult.success) throw nativeErrorFromException(chunkResult.exception, stderr);
        const chunk = chunkResult.response?.buffer || "";
        buffer += chunk;
        offset += chunk.length;
        if (!chunk.length) break;
      }
      await send("finishBufferedResponse", { streamId: result.streamId }).catch(() => {});
      return JSON.parse(buffer);
    }

    async function readSignatureBufferedContent(response) {
      const file = response?.signatureInfo?.file;
      if (!file?.streamId) return response;

      const chunks = [];
      let offset = 0;
      while (offset < file.length) {
        const chunkResult = await send("readBufferedContent", { streamId: file.streamId, offset });
        if (!chunkResult.success) throw nativeErrorFromException(chunkResult.exception, stderr);
        const written = Number(chunkResult.response?.written) || 0;
        const chunk = chunkResult.response?.buffer || "";
        if (chunk) chunks.push(Buffer.from(chunk, "base64"));
        offset += written;
        if (!written) break;
      }

      await send("finishBufferedContent", { streamId: file.streamId }).catch(() => {});
      response.signatureInfo.content = Buffer.concat(chunks).toString("base64");
      delete response.signatureInfo.file;
      return response;
    }

    async function unwrapResult(result) {
      if (isBufferedResponse(result)) {
        return readSignatureBufferedContent(await readBuffered(result));
      }
      if (!result.success) throw nativeErrorFromException(result.exception, stderr);
      return readSignatureBufferedContent(result.response);
    }

    child.stdout.on("data", (chunk) => {
      stdoutBuffer = Buffer.concat([stdoutBuffer, chunk]);
      while (stdoutBuffer.length >= 4) {
        const length = stdoutBuffer.readUInt32LE(0);
        if (stdoutBuffer.length < length + 4) break;
        const payload = stdoutBuffer.slice(4, length + 4).toString("utf8");
        stdoutBuffer = stdoutBuffer.slice(length + 4);
        let result;
        try {
          result = JSON.parse(payload);
        } catch (error) {
          finish(null, error);
          return;
        }
        const waiter = pending.get(result.requestId);
        if (waiter) {
          pending.delete(result.requestId);
          waiter.resolve(result);
        }
      }
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", () => {
      finish(null, new Error(WEB_PKI_NOT_FOUND));
    });

    child.on("exit", () => {
      if (!settled && pending.size) {
        finish(null, new Error(stderr || "O componente Web PKI foi encerrado antes de responder."));
      }
    });

    abortHandler = () => finish(null, cancelledError());
    if (signal?.aborted) {
      abortHandler();
      return;
    }
    signal?.addEventListener("abort", abortHandler, { once: true });

    (async () => {
      if (authorization) {
        const authorizationResult = await unwrapResult(await send(
          "authorizeSignatures",
          signatureAuthorizationRequest(authorization.certificateThumbprint, authorization.signatureCount)
        ));
        if (!authorizationResult?.authorized) {
          const error = new Error("Autorização para usar o certificado cancelada pelo usuário.");
          error.code = "user_cancelled";
          throw error;
        }
      }
      finish(await unwrapResult(await send(command, request)));
    })().catch((error) => finish(null, error));
  });
}

async function listCertificates(config) {
  const certificates = await runNativeCommand(config, "listCertificates", null, { timeoutMs: 60000 });
  return Array.isArray(certificates) ? certificates.map(normalizeCertificate) : [];
}

function readCertificate(config, thumbprint, options = {}) {
  return runNativeCommand(config, "readCertificate", { certificateThumbprint: thumbprint }, {
    timeoutMs: 60000,
    signal: options.signal
  });
}

function signHash(config, payload) {
  return runNativeCommand(config, "signHash", {
    certificateThumbprint: payload.thumbprint,
    hash: payload.hash,
    digestAlgorithm: payload.digestAlgorithm
  }, {
    authorizeSignatures: {
      certificateThumbprint: payload.thumbprint,
      signatureCount: 1
    },
    signal: payload.signal
  });
}

function signData(config, payload) {
  return runNativeCommand(config, "signData", {
    certificateThumbprint: payload.thumbprint,
    data: payload.data,
    digestAlgorithm: payload.digestAlgorithm
  }, {
    authorizeSignatures: {
      certificateThumbprint: payload.thumbprint,
      signatureCount: 1
    },
    signal: payload.signal
  });
}

function signPdf(config, payload) {
  return runNativeCommand(config, "signPdf", {
    content: payload.pdfBase64,
    certificateThumbprint: payload.certificateThumbprint,
    output: { mode: "returnContent" },
    trustArbitrators: [{ type: "standard", standardArbitrator: "pkiBrazil" }],
    certificateValidationLevel: "offline",
    policy: "basic"
  }, {
    authorizeSignatures: {
      certificateThumbprint: payload.certificateThumbprint,
      signatureCount: 1
    },
    signal: payload.signal
  });
}

function diagnostics() {
  const executable = resolveNativeExecutable();
  return {
    executable,
    exists: fs.existsSync(executable)
  };
}

module.exports = {
  WEB_PKI_NOT_FOUND,
  commandNeedsVisibleWindow,
  diagnostics,
  listCertificates,
  readCertificate,
  signatureAuthorizationRequest,
  signHash,
  signData,
  signPdf,
  runNativeCommand
};
