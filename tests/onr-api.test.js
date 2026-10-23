const test = require("node:test");
const assert = require("node:assert/strict");
const onrApi = require("../src/core/onr-api");

function jsonResponse(data, status = 200, statusText = "OK") {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    text: async () => JSON.stringify(data)
  };
}

test("builds a PDF signature session restricted to cryptographic devices", () => {
  const request = onrApi.buildSignatureSessionRequest({
    returnUrl: "http://127.0.0.1:1234/restpki-signature-callback?state=abc",
    contentBase64: "JVBERi0xLjQ=",
    fileName: "documento.pdf"
  });

  assert.equal(request.disableDownloads, true);
  assert.equal(request.enableBackgroundProcessing, false);
  assert.deepEqual(request.certificateRequirements, [{ type: "CryptoDevice" }]);
  assert.deepEqual(request.documents, [{
    file: {
      content: "JVBERi0xLjQ=",
      name: "documento.pdf",
      mimeType: "application/pdf",
      contentType: "application/pdf"
    },
    signatureType: "Pdf"
  }]);
});

test("builds the direct ONR signature request with the selected certificate", () => {
  const request = onrApi.buildPrepareSignatureRequest({
    contentBase64: "JVBERi0xLjQ=",
    fileName: "ato.pdf",
    certificateContent: "MIICERTIFICATE"
  });

  assert.equal(request.file.name, "ato.pdf");
  assert.equal(request.file.content, "JVBERi0xLjQ=");
  assert.deepEqual(request.certificate, { content: "MIICERTIFICATE" });
  assert.equal(request.signatureType, "Pdf");
  assert.deepEqual(request.pdfSignatureOptions, { convertToPdfA: false });
});

test("extracts and normalizes the hash returned by the ONR", () => {
  assert.deepEqual(onrApi.signatureHashParameters({
    state: "state-1",
    toSignHash: { algorithm: "SHA256", value: "AQID" }
  }), {
    state: "state-1",
    hash: "AQID",
    digestAlgorithm: "SHA-256"
  });

  assert.equal(onrApi.signatureHashParameters({
    state: "state-2",
    toSignHash: { algorithm: "SHA384", hexValue: "010203" }
  }).hash, "AQID");
});

test("builds the public validation link with the document key", () => {
  assert.equal(
    onrApi.documentValidationUrl("ABC 123", "https://assinador-web.onr.org.br/"),
    "https://assinador-web.onr.org.br/pt/docs/ABC%20123"
  );
  assert.equal(onrApi.documentValidationUrl(""), "");
});

test("prepares and completes a direct headless signature", async () => {
  const calls = [];
  const responses = [
    { success: true, state: "state-1", toSignHash: { algorithm: "SHA256", value: "AQID" } },
    { id: "document-1", key: "ABC123", signedFile: { content: "JVBERi0xLjc=" } }
  ];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return jsonResponse(responses.shift());
  };
  const config = {
    onrBaseUrl: "https://assinador-web.onr.org.br",
    onrApiKey: "PDFUtils|secret"
  };

  const prepared = await onrApi.prepareSignature(config, {
    contentBase64: "JVBERi0xLjQ=",
    fileName: "ato.pdf",
    certificateContent: "MIICERTIFICATE"
  }, { fetchImpl });
  const completed = await onrApi.completeSignature(config, {
    state: prepared.state,
    signature: "SIGNATURE"
  }, { fetchImpl });

  assert.equal(calls[0].url, "https://assinador-web.onr.org.br/api/signature");
  assert.equal(calls[1].url, "https://assinador-web.onr.org.br/api/signature/completion");
  assert.deepEqual(JSON.parse(calls[1].options.body), { state: "state-1", signature: "SIGNATURE" });
  assert.equal(onrApi.signedFileFromDocument(completed).content, "JVBERi0xLjc=");
});

test("creates a signature session on the Assinador Web ONR endpoint", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return jsonResponse({
      sessionId: "session-1",
      redirectUrl: "https://assinador-web.onr.org.br/pt/sign?token=abc"
    });
  };

  const result = await onrApi.createSignatureSession({
    onrBaseUrl: "https://assinador-web.onr.org.br/",
    onrApiKey: "PDFUtils|secret",
    onrExtraHeadersJson: "{}"
  }, {
    returnUrl: "http://127.0.0.1:1234/restpki-signature-callback?state=abc",
    contentBase64: "JVBERi0xLjQ=",
    fileName: "ato.pdf"
  }, { fetchImpl });

  assert.equal(result.sessionId, "session-1");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://assinador-web.onr.org.br/api/signature-sessions");
  assert.equal(calls[0].options.headers["X-Api-Key"], "PDFUtils|secret");
  const body = JSON.parse(calls[0].options.body);
  assert.equal(body.documents[0].file.name, "ato.pdf");
  assert.equal(body.documents[0].signatureType, "Pdf");
  assert.deepEqual(body.certificateRequirements, [{ type: "CryptoDevice" }]);
});

test("polls the Rest PKI session until it is completed", async () => {
  const statuses = ["Pending", "Processing", "Completed"];
  const observed = [];
  const fetchImpl = async () => jsonResponse({ status: statuses.shift(), documents: [] });

  const result = await onrApi.waitForSignatureSession({
    onrBaseUrl: "https://assinador-web.onr.org.br",
    onrApiKey: "PDFUtils|secret"
  }, "session-1", {
    fetchImpl,
    intervalMs: 1,
    sleep: async () => {},
    onStatus: (status) => observed.push(status)
  });

  assert.equal(result.status, "Completed");
  assert.deepEqual(observed, ["Pending", "Processing", "Completed"]);
});

test("finds and downloads a signed PDF from a relative location", async () => {
  const session = {
    documents: [{
      id: "document-1",
      key: "ABC123",
      signedFile: {
        name: "assinado.pdf",
        location: "/api/documents/document-1/signed-file?ticket=abc"
      }
    }]
  };
  const signed = onrApi.firstSignedFile(session);
  let requestedUrl = "";
  let requestedHeaders = null;
  const bytes = Buffer.from("%PDF-1.7");
  const result = await onrApi.downloadSignedFile({
    onrBaseUrl: "https://assinador-web.onr.org.br",
    onrApiKey: "PDFUtils|secret"
  }, signed.file, {
    fetchImpl: async (url, options) => {
      requestedUrl = url;
      requestedHeaders = options.headers;
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        arrayBuffer: async () => bytes
      };
    }
  });

  assert.equal(requestedUrl, "https://assinador-web.onr.org.br/api/documents/document-1/signed-file?ticket=abc");
  assert.equal(requestedHeaders["X-Api-Key"], "PDFUtils|secret");
  assert.equal(result, bytes.toString("base64"));
});

test("does not send the API key to an external temporary download URL", async () => {
  let requestedHeaders = null;
  await onrApi.downloadSignedFile({
    onrBaseUrl: "https://assinador-web.onr.org.br",
    onrApiKey: "PDFUtils|secret"
  }, {
    location: "https://storage.example.test/document.pdf?ticket=abc"
  }, {
    fetchImpl: async (_url, options) => {
      requestedHeaders = options.headers;
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        arrayBuffer: async () => Buffer.from("%PDF-1.7")
      };
    }
  });

  assert.equal(requestedHeaders["X-Api-Key"], undefined);
});

test("reports invalid and unauthorized API keys clearly", async () => {
  await assert.rejects(
    onrApi.requestJson({ onrBaseUrl: "https://assinador-web.onr.org.br", onrApiKey: "bad" }, "/api/signature-sessions", {
      fetchImpl: async () => jsonResponse({}, 401, "Unauthorized")
    }),
    /API Key está ausente ou inválida/
  );

  await assert.rejects(
    onrApi.requestJson({ onrBaseUrl: "https://assinador-web.onr.org.br", onrApiKey: "limited" }, "/api/signature-sessions", {
      fetchImpl: async () => jsonResponse({}, 403, "Forbidden")
    }),
    /não possui permissão/
  );
});
