const test = require("node:test");
const assert = require("node:assert/strict");
const webPkiNative = require("../src/core/webpki-native");

test("keeps private-key operations visible for token and PIN dialogs", () => {
  assert.equal(webPkiNative.commandNeedsVisibleWindow("listCertificates"), false);
  assert.equal(webPkiNative.commandNeedsVisibleWindow("readCertificate"), false);
  assert.equal(webPkiNative.commandNeedsVisibleWindow("authorizeSignatures"), true);
  assert.equal(webPkiNative.commandNeedsVisibleWindow("signHash"), true);
  assert.equal(webPkiNative.commandNeedsVisibleWindow("signData"), true);
  assert.equal(webPkiNative.commandNeedsVisibleWindow("signPdf"), true);
});

test("builds the certificate authorization expected by Web PKI", () => {
  assert.deepEqual(webPkiNative.signatureAuthorizationRequest("ABC123", 1), {
    certificateThumbprint: "ABC123",
    signatureCount: 1,
    enableDontAskAgain: false
  });
});

test("cancels a native operation before opening the Web PKI host", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    webPkiNative.runNativeCommand({}, "signHash", {}, { signal: controller.signal }),
    (error) => error.name === "AbortError" && /cancelada pelo usuário/.test(error.message)
  );
});
