const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const forge = require("node-forge");
const { PDFDocument } = require("pdf-lib");
const pdf = require("../src/core/pdf");
const signatureValidation = require("../src/core/signature-validation");

test("parsePdfAMetadata reads standard XMP fields", () => {
  const buffer = Buffer.from(`
    <rdf:Description>
      <pdfaid:part>1</pdfaid:part>
      <pdfaid:conformance>B</pdfaid:conformance>
    </rdf:Description>
  `);

  assert.deepEqual(pdf.parsePdfAMetadata(buffer), {
    part: "1",
    conformance: "B",
    rawFound: true
  });
});

test("ensurePdfExtension appends pdf only when needed", () => {
  assert.equal(pdf.ensurePdfExtension("saida"), "saida.pdf");
  assert.equal(pdf.ensurePdfExtension("saida.PDF"), "saida.PDF");
});

async function writeTestPdf(filePath, pageSizes) {
  const document = await PDFDocument.create();
  pageSizes.forEach(([width, height]) => document.addPage([width, height]));
  fs.writeFileSync(filePath, await document.save());
}

test("mergeFilesToPdf converts non-PDF files and preserves the selected order", async (context) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pdfutils_merge_test_"));
  context.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));
  const firstPdf = path.join(tempDir, "primeiro.pdf");
  const secondPdf = path.join(tempDir, "segundo.pdf");
  const imagePath = path.join(tempDir, "imagem.png");
  const output = path.join(tempDir, "unido.pdf");
  await writeTestPdf(firstPdf, [[200, 300]]);
  await writeTestPdf(secondPdf, [[400, 500], [410, 510]]);
  fs.writeFileSync(
    imagePath,
    Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64")
  );
  const progress = [];

  const result = await pdf.mergeFilesToPdf({
    sourcePaths: [secondPdf, imagePath, firstPdf],
    outputPath: output,
    tempDir: path.join(tempDir, "work")
  }, (message, percent) => progress.push({ message, percent }));

  const merged = await PDFDocument.load(fs.readFileSync(output));
  const sizes = merged.getPages().map((page) => [page.getWidth(), page.getHeight()]);
  assert.equal(result.sourceCount, 3);
  assert.equal(result.pageCount, 4);
  assert.deepEqual(sizes, [[400, 500], [410, 510], [1, 1], [200, 300]]);
  assert.equal(progress.at(-1).percent, 100);
  assert.match(progress[2].message, /imagem\.png/);
});

function padByteRangeValue(value) {
  return String(value).padStart(10, "0");
}

function createTestCertificate(options = {}) {
  const cpf = options.cpf || "11144477735";
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "00ABC123";
  cert.validity.notBefore = new Date("2020-01-01T00:00:00Z");
  cert.validity.notAfter = new Date("2030-01-01T00:00:00Z");
  cert.setSubject([
    { name: "organizationalUnitName", value: options.auxiliaryNumber || "12345678909" },
    { name: "commonName", value: options.commonName || `MARIA TESTE:${cpf}` },
    { type: forge.pki.oids.serialNumber, value: options.serialNumber || `CPF:${cpf}` }
  ]);
  cert.setIssuer(options.issuerCommonName ? [
    { name: "organizationName", value: options.issuerOrganization || "Gov-Br" },
    { name: "commonName", value: options.issuerCommonName }
  ] : cert.subject.attributes);
  if (options.subjectKeyIdentifier) {
    cert.setExtensions([{ name: "subjectKeyIdentifier" }]);
  }
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, keys };
}

function algorithmIdentifier(oid, parameters = null) {
  const values = [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer(oid).getBytes()
    )
  ];
  if (parameters) values.push(parameters);
  return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, values);
}

function convertSignerToRsaPss(root, privateKey) {
  const sha256Algorithm = algorithmIdentifier(
    "2.16.840.1.101.3.4.2.1",
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, "")
  );
  const mgfAlgorithm = algorithmIdentifier("1.2.840.113549.1.1.8", sha256Algorithm);
  const pssParameters = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [sha256Algorithm]),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 1, true, [mgfAlgorithm]),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 2, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.INTEGER,
        false,
        forge.asn1.integerToDer(32).getBytes()
      )
    ])
  ]);
  const signedData = root.value[1].value[0];
  const signerInfo = signedData.value[signedData.value.length - 1].value[0];
  const signedAttrs = signerInfo.value[3];
  const attrsSet = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    signedAttrs.value
  );
  const attrsDer = Buffer.from(forge.asn1.toDer(attrsSet).getBytes(), "binary");
  const signature = crypto.sign("sha256", attrsDer, {
    key: forge.pki.privateKeyToPem(privateKey),
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32
  });
  signerInfo.value[4] = algorithmIdentifier("1.2.840.113549.1.1.10", pssParameters);
  signerInfo.value[5] = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.OCTETSTRING,
    false,
    signature.toString("binary")
  );
}

function convertSignerToSubjectKeyIdentifier(root, certificate) {
  const extension = certificate.getExtension("subjectKeyIdentifier");
  const keyIdentifier = Buffer.from(extension.subjectKeyIdentifier.replace(/[^0-9a-f]/gi, ""), "hex");
  const signedData = root.value[1].value[0];
  const signerInfo = signedData.value[signedData.value.length - 1].value[0];
  signerInfo.value[0] = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.INTEGER,
    false,
    forge.asn1.integerToDer(3).getBytes()
  );
  signerInfo.value[1] = forge.asn1.create(
    forge.asn1.Class.CONTEXT_SPECIFIC,
    0,
    false,
    keyIdentifier.toString("binary")
  );
}

function convertTopLevelToBerIndefinite(der) {
  const firstLengthByte = der[1];
  const lengthByteCount = firstLengthByte < 0x80 ? 0 : (firstLengthByte & 0x7f);
  const contentOffset = firstLengthByte < 0x80 ? 2 : 2 + lengthByteCount;
  return Buffer.concat([
    Buffer.from([0x30, 0x80]),
    der.slice(contentOffset),
    Buffer.from([0x00, 0x00])
  ]);
}

function createDetachedCms(content, signingTime, certificateOptions = {}, cmsOptions = {}) {
  const { cert, keys } = createTestCertificate(certificateOptions);
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(content.toString("binary"), "binary");
  p7.addCertificate(cert);
  const authenticatedAttributes = [
    { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
    { type: forge.pki.oids.messageDigest }
  ];
  if (!cmsOptions.omitSigningTime) {
    authenticatedAttributes.push({ type: forge.pki.oids.signingTime, value: signingTime });
  }
  p7.addSigner({
    certificate: cert,
    key: keys.privateKey,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes
  });
  p7.sign({ detached: true });
  const root = p7.toAsn1();
  if (cmsOptions.rsaPss) convertSignerToRsaPss(root, keys.privateKey);
  if (cmsOptions.subjectKeyIdentifier) convertSignerToSubjectKeyIdentifier(root, cert);
  const der = Buffer.from(forge.asn1.toDer(root).getBytes(), "binary");
  return cmsOptions.berIndefinite ? convertTopLevelToBerIndefinite(der) : der;
}

function createSignedPdf(certificateOptions = {}, pdfOptions = {}) {
  const placeholder = "0".repeat(20000);
  const byteRangePlaceholder = [
    padByteRangeValue(0),
    padByteRangeValue(0),
    padByteRangeValue(0),
    padByteRangeValue(0)
  ].join(" ");
  const byteRangeEntry = `/ByteRange [${byteRangePlaceholder}]`;
  const beforeContents = [
    "%PDF-1.7\n",
    "1 0 obj\n",
    "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [3 0 R] /SigFlags 3 >> >>\n",
    "endobj\n",
    "2 0 obj\n",
    "<< /Type /Pages /Count 0 /Kids [] >>\n",
    "endobj\n",
    "3 0 obj\n",
    "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V 4 0 R >>\n",
    "endobj\n",
    "4 0 obj\n",
    `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /${pdfOptions.subFilter || "adbe.pkcs7.detached"}${pdfOptions.pdfDate ? ` /M (${pdfOptions.pdfDate})` : ""} ${pdfOptions.byteRangeAfterContents ? "" : byteRangeEntry} /Contents <`
  ].join("");
  const afterContents = `${pdfOptions.byteRangeAfterContents ? ` ${byteRangeEntry}` : ""} >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`;
  const template = Buffer.from(`${beforeContents}${placeholder}>${afterContents}`, "latin1");
  const contentsStart = beforeContents.length - 1;
  const contentsEnd = contentsStart + placeholder.length + 2;
  const byteRange = [0, contentsStart, contentsEnd, template.length - contentsEnd];
  let pdfText = template.toString("latin1").replace(
    `[${byteRangePlaceholder}]`,
    `[${byteRange.map(padByteRangeValue).join(" ")}]`
  );
  let pdfBuffer = Buffer.from(pdfText, "latin1");
  const signedBytes = Buffer.concat([
    pdfBuffer.slice(byteRange[0], byteRange[0] + byteRange[1]),
    pdfBuffer.slice(byteRange[2], byteRange[2] + byteRange[3])
  ]);
  const cms = createDetachedCms(
    signedBytes,
    new Date("2024-01-02T03:04:05Z"),
    certificateOptions,
    pdfOptions.cmsOptions
  );
  const cmsHex = cms.toString("hex").toUpperCase();
  assert.ok(cmsHex.length <= placeholder.length);
  pdfText = pdfText.replace(placeholder, cmsHex.padEnd(placeholder.length, "0"));
  return Buffer.from(pdfText, "latin1");
}

test("validateSignaturesFromBuffer reports valid PDF signatures", () => {
  const result = signatureValidation.validateSignaturesFromBuffer(createSignedPdf());
  assert.equal(result.hasValidSignatures, true);
  assert.equal(result.signatures.length, 1);
  assert.equal(result.signatures[0].valid, true);
  assert.equal(result.signatures[0].name, "MARIA TESTE");
  assert.equal(result.signatures[0].cpf, "111.444.777-35");
  assert.equal(result.signatures[0].certificateSerialNumber, "00ABC123");
  assert.equal(result.signatures[0].signingTime, "2024-01-02T03:04:05.000Z");
});

test("validateSignaturesFromBuffer ignores auxiliary numbers when extracting CPF", () => {
  const result = signatureValidation.validateSignaturesFromBuffer(createSignedPdf({
    auxiliaryNumber: "12345678909",
    cpf: "11144477735"
  }));
  assert.equal(result.hasValidSignatures, true);
  assert.equal(result.signatures[0].cpf, "111.444.777-35");
});

test("validateSignaturesFromBuffer does not show invalid CPF numbers", () => {
  const result = signatureValidation.validateSignaturesFromBuffer(createSignedPdf({
    auxiliaryNumber: "12345678909",
    commonName: "MARIA TESTE:00000000000",
    serialNumber: "CPF:00000000000"
  }));
  assert.equal(result.hasValidSignatures, true);
  assert.equal(result.signatures[0].cpf, "");
});

test("validateSignaturesFromBuffer returns no valid signatures for unsigned PDFs", () => {
  const result = signatureValidation.validateSignaturesFromBuffer(Buffer.from("%PDF-1.7\n%%EOF\n"));
  assert.equal(result.hasValidSignatures, false);
  assert.deepEqual(result.signatures, []);
});

test("parsePdfDate reads timezone offsets used by PAdES signatures", () => {
  assert.equal(
    signatureValidation.parsePdfDate("D:20240722123456-03'00'"),
    "2024-07-22T15:34:56.000Z"
  );
});

test("validates advanced PAdES signatures using RSA-PSS and subject key identifiers", () => {
  const result = signatureValidation.validateSignaturesFromBuffer(createSignedPdf(
    { subjectKeyIdentifier: true },
    {
      subFilter: "ETSI.CAdES.detached",
      pdfDate: "D:20240722123456-03'00'",
      cmsOptions: {
        omitSigningTime: true,
        rsaPss: true,
        subjectKeyIdentifier: true
      }
    }
  ));

  assert.equal(result.hasValidSignatures, true);
  assert.equal(result.signatures.length, 1);
  assert.equal(result.signatures[0].valid, true);
  assert.match(result.signatures[0].format, /PAdES/);
  assert.equal(result.signatures[0].subFilter, "ETSI.CAdES.detached");
  assert.equal(result.signatures[0].signingTime, "2024-07-22T15:34:56.000Z");
  assert.equal(result.signatures[0].timeSource, "pdf");
});

test("validates gov.br-style BER signatures with ByteRange after Contents", () => {
  const result = signatureValidation.validateSignaturesFromBuffer(createSignedPdf(
    {
      issuerCommonName: "AC Final do Governo Federal do Brasil v1",
      issuerOrganization: "Gov-Br"
    },
    {
      subFilter: "adbe.pkcs7.detached",
      pdfDate: "D:20240722123456-03'00'",
      byteRangeAfterContents: true,
      cmsOptions: {
        omitSigningTime: true,
        berIndefinite: true
      }
    }
  ));

  assert.equal(result.hasValidSignatures, true);
  assert.equal(result.signatures.length, 1);
  assert.equal(result.signatures[0].format, "Assinatura avançada gov.br");
  assert.equal(result.signatures[0].subFilter, "adbe.pkcs7.detached");
  assert.equal(result.signatures[0].signingTime, "2024-07-22T15:34:56.000Z");
});
