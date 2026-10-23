const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const forge = require("node-forge");

const SIGNATURE_CONTENTS_PADDING = 0x00;
const CMS_SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
const CMS_DATA_OID = "1.2.840.113549.1.7.1";
const TST_INFO_OID = "1.2.840.113549.1.9.16.1.4";

const DIGEST_OIDS = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.4": "sha224",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512"
};

const SIGNATURE_DIGEST_OIDS = {
  "1.2.840.113549.1.1.5": "sha1",
  "1.2.840.113549.1.1.14": "sha224",
  "1.2.840.113549.1.1.11": "sha256",
  "1.2.840.113549.1.1.12": "sha384",
  "1.2.840.113549.1.1.13": "sha512",
  "1.2.840.10045.4.1": "sha1",
  "1.2.840.10045.4.3.1": "sha224",
  "1.2.840.10045.4.3.2": "sha256",
  "1.2.840.10045.4.3.3": "sha384",
  "1.2.840.10045.4.3.4": "sha512"
};

const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
const RSA_PSS_OID = "1.2.840.113549.1.1.10";
const MGF1_OID = "1.2.840.113549.1.1.8";
const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
const MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";
const SIGNING_CERTIFICATE_OID = "1.2.840.113549.1.9.16.2.12";
const SIGNING_CERTIFICATE_V2_OID = "1.2.840.113549.1.9.16.2.47";
const SIGNATURE_TIMESTAMP_OID = "1.2.840.113549.1.9.16.2.14";
const ICP_BRASIL_PF_DATA_OID = "2.16.76.1.3.1";
const GOV_BR_TRUSTED_ROOT_SHA256 = [
  "163BD003BC0DF2BEAB88174B6D5B450B6E1DC973A64B2DC2A33218544F49EF4E"
];

function bytesToBuffer(bytes) {
  return Buffer.from(bytes || "", "binary");
}

function bufferToBytes(buffer) {
  return Buffer.from(buffer || Buffer.alloc(0)).toString("binary");
}

function asn1Oid(node) {
  if (!node || node.type !== forge.asn1.Type.OID) return "";
  return forge.asn1.derToOid(node.value);
}

function algorithmOid(algorithmIdentifier) {
  return asn1Oid(algorithmIdentifier?.value?.[0]);
}

function integerBytesToHex(bytes) {
  const hex = bytesToBuffer(bytes).toString("hex").replace(/^0+/, "");
  return (hex || "0").toUpperCase();
}

function asn1IntegerToNumber(node, fallback) {
  if (!node || node.type !== forge.asn1.Type.INTEGER) return fallback;
  const bytes = bytesToBuffer(node.value);
  let value = 0;
  for (const byte of bytes) {
    value = (value * 256) + byte;
    if (!Number.isSafeInteger(value)) return fallback;
  }
  return value;
}

function normalizeSerial(serial) {
  return String(serial || "").replace(/[^0-9a-f]/gi, "").replace(/^0+/, "").toUpperCase() || "0";
}

function formatCertificateSerial(serial) {
  return String(serial || "").replace(/[^0-9a-f]/gi, "").toUpperCase() || "";
}

function parseByteRange(text, startIndex) {
  const match = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g.exec(text.slice(startIndex));
  if (!match) return null;
  return {
    index: startIndex + match.index,
    byteRange: match.slice(1).map((value) => Number(value))
  };
}

function isValidByteRange(byteRange, size) {
  if (!Array.isArray(byteRange) || byteRange.length !== 4) return false;
  if (byteRange.some((value) => !Number.isInteger(value) || value < 0)) return false;
  const [firstOffset, firstLength, secondOffset, secondLength] = byteRange;
  if (firstOffset !== 0) return false;
  if (firstOffset + firstLength > secondOffset) return false;
  if (secondOffset + secondLength > size) return false;
  return true;
}

function derObjectLength(buffer) {
  if (!buffer.length || buffer[0] !== 0x30 || buffer.length < 2) return 0;
  const firstLengthByte = buffer[1];
  if (firstLengthByte < 0x80) return 2 + firstLengthByte;
  const lengthByteCount = firstLengthByte & 0x7f;
  if (!lengthByteCount || lengthByteCount > 6 || buffer.length < 2 + lengthByteCount) return 0;
  let contentLength = 0;
  for (let index = 0; index < lengthByteCount; index += 1) {
    contentLength = (contentLength * 256) + buffer[2 + index];
    if (!Number.isSafeInteger(contentLength)) return 0;
  }
  return 2 + lengthByteCount + contentLength;
}

function extractContents(buffer, byteRange) {
  const gapStart = byteRange[0] + byteRange[1];
  const gapEnd = byteRange[2];
  const gap = buffer.slice(gapStart, gapEnd).toString("latin1");
  const match = gap.match(/<([0-9a-fA-F\s]+)>/);
  if (!match) return null;
  const hex = match[1].replace(/\s+/g, "");
  if (!hex || hex.length % 2 !== 0) return null;
  let contents = Buffer.from(hex, "hex");
  const declaredLength = derObjectLength(contents);
  if (declaredLength > 0 && declaredLength <= contents.length) {
    contents = contents.slice(0, declaredLength);
  } else if (contents[0] === 0x30 && contents[1] === 0x80) {
    try {
      const asn1Buffer = forge.util.createBuffer(bufferToBytes(contents));
      forge.asn1.fromDer(asn1Buffer, { strict: true, parseAllBytes: false });
      contents = contents.slice(0, contents.length - asn1Buffer.length());
    } catch (_) {
      return null;
    }
  } else {
    while (contents.length && contents[contents.length - 1] === SIGNATURE_CONTENTS_PADDING) {
      contents = contents.slice(0, -1);
    }
  }
  return contents.length ? contents : null;
}

function extractSignedBytes(buffer, byteRange) {
  return Buffer.concat([
    buffer.slice(byteRange[0], byteRange[0] + byteRange[1]),
    buffer.slice(byteRange[2], byteRange[2] + byteRange[3])
  ]);
}

function decodePdfLiteralString(value) {
  return String(value || "")
    .replace(/\\([nrtbf()\\])/g, (_match, escaped) => ({
      n: "\n",
      r: "\r",
      t: "\t",
      b: "\b",
      f: "\f",
      "(": "(",
      ")": ")",
      "\\": "\\"
    })[escaped])
    .replace(/\\([0-7]{1,3})/g, (_match, octal) => String.fromCharCode(parseInt(octal, 8)));
}

function parsePdfDate(value) {
  const match = String(value || "").match(
    /^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([Zz+\-])(\d{2})?'?(\d{2})?'?)?/
  );
  if (!match) return "";
  const year = Number(match[1]);
  const month = Number(match[2] || 1) - 1;
  const day = Number(match[3] || 1);
  const hour = Number(match[4] || 0);
  const minute = Number(match[5] || 0);
  const second = Number(match[6] || 0);
  let timestamp = Date.UTC(year, month, day, hour, minute, second);
  if (match[7] === "+" || match[7] === "-") {
    const offset = ((Number(match[8] || 0) * 60) + Number(match[9] || 0)) * 60 * 1000;
    timestamp += match[7] === "+" ? -offset : offset;
  }
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function extractSignatureMetadata(text, byteRangeIndex, byteRange) {
  const typeIndex = text.lastIndexOf("/Type /Sig", byteRangeIndex);
  const objectIndex = text.lastIndexOf(" obj", byteRangeIndex);
  const start = typeIndex >= 0
    ? Math.max(0, typeIndex - 1024)
    : (objectIndex >= 0 ? objectIndex : Math.max(0, byteRangeIndex - 65536));
  const end = Math.min(text.length, byteRange[2] + 4096);
  const dictionary = text.slice(start, end);
  const subFilter = dictionary.match(/\/SubFilter\s*\/([^\s/<>\[\]()]+)/)?.[1] || "";
  const pdfDateValue = dictionary.match(/\/M\s*\((D:[^)]*)\)/)?.[1] || "";
  const nameValue = dictionary.match(/\/Name\s*\(([^)]*(?:\\\)[^)]*)*)\)/)?.[1] || "";
  return {
    subFilter,
    pdfSigningTime: parsePdfDate(decodePdfLiteralString(pdfDateValue)),
    pdfSignerName: decodePdfLiteralString(nameValue).trim()
  };
}

function extractPdfSignatures(buffer) {
  const text = buffer.toString("latin1");
  const signatures = [];
  let offset = 0;
  while (offset < text.length) {
    const found = parseByteRange(text, offset);
    if (!found) break;
    offset = found.index + 10;
    if (!isValidByteRange(found.byteRange, buffer.length)) continue;
    const contents = extractContents(buffer, found.byteRange);
    if (!contents) continue;
    signatures.push({
      byteRange: found.byteRange,
      contents,
      signedBytes: extractSignedBytes(buffer, found.byteRange),
      coversWholeFile: found.byteRange[2] + found.byteRange[3] === buffer.length,
      hasLongTermValidationData: /\/DSS(?:\s|<)/.test(text),
      ...extractSignatureMetadata(text, found.index, found.byteRange)
    });
  }
  return signatures;
}

function extractOctets(node) {
  if (!node) return Buffer.alloc(0);
  if (node.type === forge.asn1.Type.OCTETSTRING && typeof node.value === "string") {
    return bytesToBuffer(node.value);
  }
  if (!Array.isArray(node.value)) return Buffer.alloc(0);
  return Buffer.concat(node.value.map(extractOctets));
}

function parseSignedDataAsn1(input) {
  const contentInfo = Buffer.isBuffer(input)
    ? forge.asn1.fromDer(bufferToBytes(input))
    : input;
  if (!contentInfo || asn1Oid(contentInfo.value?.[0]) !== CMS_SIGNED_DATA_OID) {
    throw new Error("O conteúdo não é um CMS SignedData.");
  }
  const signedData = contentInfo.value?.[1]?.value?.[0];
  const values = Array.isArray(signedData?.value) ? signedData.value : [];
  if (values.length < 4) throw new Error("CMS SignedData incompleto.");

  const encapContentInfo = values[2];
  const eContentType = asn1Oid(encapContentInfo?.value?.[0]);
  const eContent = extractOctets(encapContentInfo?.value?.[1]);
  let index = 3;
  const certificates = [];
  if (values[index]?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && values[index]?.type === 0) {
    for (const certificateNode of values[index].value || []) {
      try {
        if (certificateNode.tagClass === forge.asn1.Class.UNIVERSAL) {
          certificates.push(forge.pki.certificateFromAsn1(certificateNode));
        }
      } catch (_) {
        // Attribute certificates are allowed in this collection and are not signer certificates.
      }
    }
    index += 1;
  }
  if (values[index]?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && values[index]?.type === 1) {
    index += 1;
  }
  const signerInfos = values[index]?.value || [];
  return { certificates, eContentType, eContent, signerInfos };
}

function signerInfoParts(signerInfo) {
  const values = Array.isArray(signerInfo?.value) ? signerInfo.value : [];
  let index = 0;
  const version = values[index++];
  const sid = values[index++];
  const digestAlgorithm = values[index++];
  let signedAttrs = null;
  if (values[index]?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && values[index]?.type === 0) {
    signedAttrs = values[index++];
  }
  const signatureAlgorithm = values[index++];
  const signature = values[index++];
  let unsignedAttrs = null;
  if (values[index]?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && values[index]?.type === 1) {
    unsignedAttrs = values[index];
  }
  return {
    version,
    sid,
    digestAlgorithm,
    signedAttrs,
    signatureAlgorithm,
    signature,
    unsignedAttrs
  };
}

function serialFromSid(sid) {
  if (!sid || sid.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) return "";
  const serial = sid.value?.[1];
  return integerBytesToHex(serial?.value || "");
}

function subjectKeyIdentifierFromSid(sid) {
  if (!sid || sid.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC || sid.type !== 0) return "";
  const value = typeof sid.value === "string" ? bytesToBuffer(sid.value) : extractOctets(sid);
  return value.toString("hex").toUpperCase();
}

function certificateSubjectKeyIdentifier(certificate) {
  const extension = (certificate.extensions || []).find(
    (item) => item.name === "subjectKeyIdentifier" || item.id === "2.5.29.14"
  );
  const extensionValue = String(extension?.subjectKeyIdentifier || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
  if (extensionValue) return extensionValue;
  try {
    const subjectPublicKeyInfo = forge.pki.publicKeyToAsn1(certificate.publicKey);
    const bitString = bytesToBuffer(subjectPublicKeyInfo.value?.[1]?.value || "");
    const publicKeyBytes = bitString.length && bitString[0] === 0 ? bitString.slice(1) : bitString;
    return crypto.createHash("sha1").update(publicKeyBytes).digest("hex").toUpperCase();
  } catch (_) {
    return "";
  }
}

function findSignerCertificate(certificates, signerInfo) {
  const sid = signerInfoParts(signerInfo).sid;
  const subjectKeyIdentifier = subjectKeyIdentifierFromSid(sid);
  if (subjectKeyIdentifier) {
    const byKeyIdentifier = certificates.find(
      (certificate) => certificateSubjectKeyIdentifier(certificate) === subjectKeyIdentifier
    );
    if (byKeyIdentifier) return byKeyIdentifier;
  }
  const serial = normalizeSerial(serialFromSid(sid));
  if (serial) {
    const bySerial = certificates.find((certificate) => normalizeSerial(certificate.serialNumber) === serial);
    if (bySerial) return bySerial;
  }
  return certificates[0] || null;
}

function signedAttrsAsSetDer(signedAttrs) {
  const set = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    signedAttrs.value || []
  );
  return bytesToBuffer(forge.asn1.toDer(set).getBytes());
}

function parseAttributeMap(attributes) {
  const result = new Map();
  for (const attribute of attributes?.value || []) {
    const oid = asn1Oid(attribute.value?.[0]);
    const values = attribute.value?.[1]?.value || [];
    if (oid) result.set(oid, values);
  }
  return result;
}

function parseSigningTime(value) {
  if (!value) return "";
  try {
    if (value.type === forge.asn1.Type.UTCTIME) return forge.asn1.utcTimeToDate(value.value).toISOString();
    if (value.type === forge.asn1.Type.GENERALIZEDTIME) {
      return forge.asn1.generalizedTimeToDate(value.value).toISOString();
    }
  } catch (_) {
    return "";
  }
  return "";
}

function verifyMessageDigest(digestName, signedBytes, signedAttrs) {
  if (!signedAttrs) return true;
  const attrs = parseAttributeMap(signedAttrs);
  const digestValue = attrs.get(MESSAGE_DIGEST_OID)?.[0]?.value;
  if (!digestValue) return false;
  const expected = bytesToBuffer(digestValue);
  const actual = crypto.createHash(digestName).update(signedBytes).digest();
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function parseRsaPssParameters(algorithmIdentifier, fallbackDigest) {
  const result = {
    digestName: fallbackDigest || "sha1",
    mgfDigestName: fallbackDigest || "sha1",
    saltLength: 20
  };
  const parameters = algorithmIdentifier?.value?.[1];
  if (!parameters || !Array.isArray(parameters.value)) return result;
  for (const parameter of parameters.value) {
    const explicitValue = parameter.value?.[0];
    if (parameter.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC || !explicitValue) continue;
    if (parameter.type === 0) {
      result.digestName = DIGEST_OIDS[algorithmOid(explicitValue)] || "";
    } else if (parameter.type === 1) {
      if (algorithmOid(explicitValue) !== MGF1_OID) {
        result.mgfDigestName = "";
      } else {
        result.mgfDigestName = DIGEST_OIDS[algorithmOid(explicitValue.value?.[1])] || "";
      }
    } else if (parameter.type === 2) {
      result.saltLength = asn1IntegerToNumber(explicitValue, result.saltLength);
    }
  }
  return result;
}

function verifySignerSignature({ certificate, signerInfo, digestName, signedBytes }) {
  const parts = signerInfoParts(signerInfo);
  if (!parts.signature?.value) return false;
  const data = parts.signedAttrs ? signedAttrsAsSetDer(parts.signedAttrs) : signedBytes;
  const signature = bytesToBuffer(parts.signature.value);
  const certificatePem = forge.pki.certificateToPem(certificate);
  const signatureAlgorithmOid = algorithmOid(parts.signatureAlgorithm);

  if (signatureAlgorithmOid === RSA_PSS_OID) {
    const pss = parseRsaPssParameters(parts.signatureAlgorithm, digestName);
    if (!pss.digestName || pss.digestName !== digestName || pss.mgfDigestName !== pss.digestName) return false;
    return crypto.verify(pss.digestName, data, {
      key: certificatePem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: pss.saltLength
    }, signature);
  }

  const signatureDigest = SIGNATURE_DIGEST_OIDS[signatureAlgorithmOid]
    || (signatureAlgorithmOid === RSA_ENCRYPTION_OID ? digestName : "");
  if (!signatureDigest || signatureDigest !== digestName) return false;
  return crypto.verify(signatureDigest, data, certificatePem, signature);
}

function certificateDer(certificate) {
  return bytesToBuffer(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes());
}

function verifyCertificateReference(signedAttrs, certificate) {
  const attrs = parseAttributeMap(signedAttrs);
  const v2 = attrs.get(SIGNING_CERTIFICATE_V2_OID)?.[0];
  const v1 = attrs.get(SIGNING_CERTIFICATE_OID)?.[0];
  const value = v2 || v1;
  if (!value) return { present: false, valid: true };
  try {
    const certsSequence = value.value?.[0];
    const certId = certsSequence?.value?.[0];
    const fields = certId?.value || [];
    let digestName = v2 ? "sha256" : "sha1";
    let hashNode = fields[0];
    if (v2 && fields[0]?.type === forge.asn1.Type.SEQUENCE) {
      digestName = DIGEST_OIDS[algorithmOid(fields[0])] || "";
      hashNode = fields[1];
    }
    if (!digestName || hashNode?.type !== forge.asn1.Type.OCTETSTRING) {
      return { present: true, valid: false };
    }
    const expected = bytesToBuffer(hashNode.value);
    const actual = crypto.createHash(digestName).update(certificateDer(certificate)).digest();
    return {
      present: true,
      valid: expected.length === actual.length && crypto.timingSafeEqual(expected, actual)
    };
  } catch (_) {
    return { present: true, valid: false };
  }
}

function certificateValidAt(certificate, signingTimeIso) {
  const when = signingTimeIso ? new Date(signingTimeIso) : new Date();
  if (Number.isNaN(when.getTime())) return false;
  return certificate.validity.notBefore <= when && certificate.validity.notAfter >= when;
}

function certificateAttributeText(certificate, collection) {
  return (certificate?.[collection]?.attributes || [])
    .map((attribute) => String(attribute.value || ""))
    .join(" ");
}

function signerName(certificate, fallbackName = "") {
  const cn = certificate.subject.getField("CN")?.value || fallbackName;
  if (!cn) return "Assinante não identificado";
  return cn
    .replace(/[:\s-]*(CPF|CNPJ)?[:\s-]*(\d{3}\.?\d{3}\.?\d{3}-?\d{2}|\*{3}\.?\d{3}\.?\d{3}-?\*{2}).*/i, "")
    .trim() || cn.trim();
}

function certificateIssuer(certificate) {
  return certificate.issuer.getField("CN")?.value
    || certificateAttributeText(certificate, "issuer")
    || "não informado";
}

function cpfDigits(value) {
  return String(value || "").replace(/\D/g, "");
}

function isValidCpf(value) {
  const digits = cpfDigits(value);
  if (digits.length !== 11 || /^(\d)\1{10}$/.test(digits)) return false;
  const calc = (length) => {
    let sum = 0;
    for (let index = 0; index < length; index += 1) {
      sum += Number(digits[index]) * (length + 1 - index);
    }
    const rest = (sum * 10) % 11;
    return rest === 10 ? 0 : rest;
  };
  return calc(9) === Number(digits[9]) && calc(10) === Number(digits[10]);
}

function formatCpf(value) {
  const digits = cpfDigits(value);
  if (isValidCpf(digits)) {
    return `${digits.slice(0, 3)}.${digits.slice(3, 6)}.${digits.slice(6, 9)}-${digits.slice(9)}`;
  }
  return "";
}

function findFullCpf(value) {
  const text = String(value || "");
  const pattern = /(^|\D)(\d{3})\.?(\d{3})\.?(\d{3})-?(\d{2})(?=\D|$)/g;
  for (const match of text.matchAll(pattern)) {
    const formatted = formatCpf(`${match[2]}${match[3]}${match[4]}${match[5]}`);
    if (formatted) return formatted;
  }
  return "";
}

function findMaskedCpf(value) {
  const text = String(value || "");
  const masked = text.match(/(\*{3})\.?(\d{3})\.?(\d{3})-?(\*{2})/);
  if (masked) return `${masked[1]}.${masked[2]}.${masked[3]}-${masked[4]}`;
  return "";
}

function otherNameValue(otherName) {
  const values = Array.isArray(otherName?.value) ? otherName.value : [];
  const oid = asn1Oid(values[0]);
  const wrapped = values[1]?.value?.[0];
  return { oid, value: wrapped?.value || "" };
}

function icpBrasilPessoaFisicaCpf(certificate) {
  for (const extension of certificate.extensions || []) {
    if (extension.name !== "subjectAltName") continue;
    for (const altName of extension.altNames || []) {
      if (altName.type !== 0) continue;
      const { oid, value } = otherNameValue(altName);
      if (oid !== ICP_BRASIL_PF_DATA_OID) continue;
      const digits = cpfDigits(value);
      if (digits.length >= 19) {
        const formatted = formatCpf(digits.slice(8, 19));
        if (formatted) return formatted;
      }
    }
  }
  return "";
}

function signerCpf(certificate) {
  const cn = certificate.subject.getField("CN")?.value || "";
  const serial = certificate.subject.getField({ type: forge.pki.oids.serialNumber })?.value || "";
  const subjectValues = certificate.subject.attributes.map((attribute) => attribute.value || "");
  return (
    findFullCpf(cn)
    || findFullCpf(serial)
    || icpBrasilPessoaFisicaCpf(certificate)
    || subjectValues.map(findMaskedCpf).find(Boolean)
    || ""
  );
}

function isIcpBrasilCertificate(certificate) {
  const text = `${certificateAttributeText(certificate, "subject")} ${certificateAttributeText(certificate, "issuer")}`;
  return /ICP-?Brasil/i.test(text) || Boolean(icpBrasilPessoaFisicaCpf(certificate));
}

function isGovBrCertificate(certificate) {
  const text = `${certificateAttributeText(certificate, "subject")} ${certificateAttributeText(certificate, "issuer")}`;
  return /Governo Federal do Brasil|Gov-?Br/i.test(text);
}

function parseTstInfo(buffer) {
  const tstInfo = forge.asn1.fromDer(bufferToBytes(buffer));
  const values = tstInfo?.value || [];
  const messageImprint = values[2];
  const digestName = DIGEST_OIDS[algorithmOid(messageImprint?.value?.[0])];
  const hashedMessage = bytesToBuffer(messageImprint?.value?.[1]?.value || "");
  const generatedAt = parseSigningTime(values[4]);
  if (!digestName || !hashedMessage.length || !generatedAt) {
    throw new Error("TSTInfo inválido.");
  }
  return { digestName, hashedMessage, generatedAt };
}

function equalDigest(digestName, data, expected) {
  const actual = crypto.createHash(digestName).update(data).digest();
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function validateTimestampToken(input, expectedData) {
  try {
    const signedData = parseSignedDataAsn1(input);
    if (signedData.eContentType !== TST_INFO_OID || !signedData.eContent.length) {
      return { present: true, valid: false, signingTime: "" };
    }
    const tstInfo = parseTstInfo(signedData.eContent);
    if (!equalDigest(tstInfo.digestName, expectedData, tstInfo.hashedMessage)) {
      return { present: true, valid: false, signingTime: tstInfo.generatedAt };
    }
    for (const signerInfo of signedData.signerInfos) {
      const parts = signerInfoParts(signerInfo);
      const digestName = DIGEST_OIDS[algorithmOid(parts.digestAlgorithm)];
      const certificate = findSignerCertificate(signedData.certificates, signerInfo);
      if (!digestName || !certificate) continue;
      const digestValid = verifyMessageDigest(digestName, signedData.eContent, parts.signedAttrs);
      const signatureValid = verifySignerSignature({
        certificate,
        signerInfo,
        digestName,
        signedBytes: signedData.eContent
      });
      const certificateReference = verifyCertificateReference(parts.signedAttrs, certificate);
      const timeValid = certificateValidAt(certificate, tstInfo.generatedAt);
      if (digestValid && signatureValid && certificateReference.valid && timeValid) {
        return {
          present: true,
          valid: true,
          signingTime: tstInfo.generatedAt,
          authority: signerName(certificate),
          certificate
        };
      }
    }
  } catch (_) {
    // A malformed timestamp does not invalidate the main document signature.
  }
  return { present: true, valid: false, signingTime: "" };
}

function validateSignatureTimestamp(unsignedAttrs, signatureValue) {
  const timestampToken = parseAttributeMap(unsignedAttrs).get(SIGNATURE_TIMESTAMP_OID)?.[0];
  if (!timestampToken) return { present: false, valid: false, signingTime: "" };
  return validateTimestampToken(timestampToken, signatureValue);
}

function defaultTrustResult(status = "indeterminate") {
  return {
    trustStatus: status,
    chainTrusted: false,
    revocationStatus: "not-checked",
    trustDetails: []
  };
}

function validateWindowsTrust(certificate, certificates, signingTime) {
  if (process.platform !== "win32") return defaultTrustResult();
  const scriptPath = path.join(__dirname, "windows-certificate-trust.ps1");
  if (!fs.existsSync(scriptPath)) return defaultTrustResult();
  try {
    const leafDer = certificateDer(certificate);
    const intermediates = certificates
      .filter((item) => item !== certificate)
      .map((item) => certificateDer(item).toString("base64"));
    const payload = JSON.stringify({
      leaf: leafDer.toString("base64"),
      intermediates,
      verificationTime: signingTime || new Date().toISOString(),
      trustedRootSha256: isGovBrCertificate(certificate) ? GOV_BR_TRUSTED_ROOT_SHA256 : []
    });
    const result = spawnSync("powershell.exe", [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      scriptPath
    ], {
      input: payload,
      encoding: "utf8",
      windowsHide: true,
      timeout: 15000,
      maxBuffer: 1024 * 1024
    });
    if (result.error || result.status !== 0 || !result.stdout.trim()) return defaultTrustResult();
    const trust = JSON.parse(result.stdout);
    return {
      trustStatus: trust.chainTrusted ? "trusted" : "untrusted",
      chainTrusted: Boolean(trust.chainTrusted),
      revocationStatus: trust.revocationStatus || "not-checked",
      trustDetails: Array.isArray(trust.statuses) ? trust.statuses : []
    };
  } catch (_) {
    return defaultTrustResult();
  }
}

function signatureFormat(pdfSignature, certificate, timestamp) {
  if (pdfSignature.subFilter === "ETSI.RFC3161") return "Carimbo do tempo RFC 3161";
  if (isGovBrCertificate(certificate)) {
    return `Assinatura avançada gov.br${timestamp.present && timestamp.valid ? " com carimbo do tempo" : ""}`;
  }
  const isPades = pdfSignature.subFilter === "ETSI.CAdES.detached";
  const qualification = isIcpBrasilCertificate(certificate)
    ? "qualificada ICP-Brasil"
    : "avançada";
  if (isPades) {
    return `Assinatura ${qualification} PAdES${timestamp.present && timestamp.valid ? " com carimbo do tempo" : ""}`;
  }
  if (/^adbe\.pkcs7/i.test(pdfSignature.subFilter)) {
    return `Assinatura PDF Adobe/CMS${timestamp.present && timestamp.valid ? " com carimbo do tempo" : ""}`;
  }
  return "Assinatura digital CMS/PAdES";
}

function validateDocumentTimestamp(pdfSignature, options) {
  const timestamp = validateTimestampToken(pdfSignature.contents, pdfSignature.signedBytes);
  if (!timestamp.valid || !timestamp.certificate) return [];
  const trust = options.checkTrust
    ? validateWindowsTrust(timestamp.certificate, [timestamp.certificate], timestamp.signingTime)
    : defaultTrustResult("not-checked");
  if (trust.revocationStatus === "revoked") return [];
  return [{
    valid: true,
    documentTimestamp: true,
    name: timestamp.authority || "Autoridade de carimbo do tempo",
    cpf: "",
    certificateSerialNumber: formatCertificateSerial(timestamp.certificate.serialNumber),
    certificateIssuer: certificateIssuer(timestamp.certificate),
    signingTime: timestamp.signingTime,
    timeSource: "timestamp",
    format: "Carimbo do tempo RFC 3161",
    timestampPresent: true,
    timestampValid: true,
    timestampAuthority: timestamp.authority || "",
    coversWholeFile: pdfSignature.coversWholeFile,
    hasLaterRevisions: !pdfSignature.coversWholeFile,
    hasLongTermValidationData: pdfSignature.hasLongTermValidationData,
    ...trust
  }];
}

function validateCmsSignature(pdfSignature, options = {}) {
  if (pdfSignature.subFilter === "ETSI.RFC3161") {
    return validateDocumentTimestamp(pdfSignature, options);
  }
  const message = parseSignedDataAsn1(pdfSignature.contents);
  const validSignatures = [];

  for (const signerInfo of message.signerInfos) {
    try {
      const parts = signerInfoParts(signerInfo);
      const digestName = DIGEST_OIDS[algorithmOid(parts.digestAlgorithm)];
      const certificate = findSignerCertificate(message.certificates, signerInfo);
      if (!digestName || !certificate) continue;

      const attrs = parseAttributeMap(parts.signedAttrs);
      const cmsSigningTime = parseSigningTime(attrs.get(SIGNING_TIME_OID)?.[0]);
      const signatureValue = bytesToBuffer(parts.signature?.value || "");
      const timestamp = validateSignatureTimestamp(parts.unsignedAttrs, signatureValue);
      const signingTime = timestamp.valid
        ? timestamp.signingTime
        : (cmsSigningTime || pdfSignature.pdfSigningTime);
      const timeSource = timestamp.valid
        ? "timestamp"
        : (cmsSigningTime ? "cms" : (pdfSignature.pdfSigningTime ? "pdf" : "unknown"));
      const digestValid = verifyMessageDigest(digestName, pdfSignature.signedBytes, parts.signedAttrs);
      const signatureValid = verifySignerSignature({
        certificate,
        signerInfo,
        digestName,
        signedBytes: pdfSignature.signedBytes
      });
      const certificateReference = verifyCertificateReference(parts.signedAttrs, certificate);
      const timeValid = certificateValidAt(certificate, signingTime);
      if (!digestValid || !signatureValid || !certificateReference.valid || !timeValid) continue;

      const trust = options.checkTrust
        ? validateWindowsTrust(certificate, message.certificates, signingTime)
        : defaultTrustResult("not-checked");
      if (trust.revocationStatus === "revoked") continue;
      validSignatures.push({
        valid: true,
        documentTimestamp: false,
        name: signerName(certificate, pdfSignature.pdfSignerName),
        cpf: signerCpf(certificate),
        certificateSerialNumber: formatCertificateSerial(certificate.serialNumber),
        certificateIssuer: certificateIssuer(certificate),
        signingTime,
        timeSource,
        format: signatureFormat(pdfSignature, certificate, timestamp),
        subFilter: pdfSignature.subFilter,
        certificateReferencePresent: certificateReference.present,
        timestampPresent: timestamp.present,
        timestampValid: timestamp.valid,
        timestampAuthority: timestamp.authority || "",
        coversWholeFile: pdfSignature.coversWholeFile,
        hasLaterRevisions: !pdfSignature.coversWholeFile,
        hasLongTermValidationData: pdfSignature.hasLongTermValidationData,
        ...trust
      });
    } catch (_) {
      // Ignore malformed signer entries and keep validating the remaining ones.
    }
  }

  return validSignatures;
}

function validateSignaturesFromBuffer(buffer, options = {}) {
  const validSignatures = [];
  for (const pdfSignature of extractPdfSignatures(buffer)) {
    try {
      validSignatures.push(...validateCmsSignature(pdfSignature, options));
    } catch (_) {
      // An invalid CMS blob is not a valid PDF signature.
    }
  }
  return {
    signatures: validSignatures,
    hasValidSignatures: validSignatures.length > 0
  };
}

function validatePdfSignatures(data) {
  const source = path.resolve(data?.sourcePath || "");
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) {
    throw new Error("Selecione um PDF válido para validar assinaturas.");
  }
  if (path.extname(source).toLowerCase() !== ".pdf") {
    throw new Error("A validação de assinaturas aceita apenas arquivos PDF.");
  }
  return validateSignaturesFromBuffer(fs.readFileSync(source), { checkTrust: true });
}

module.exports = {
  extractPdfSignatures,
  parsePdfDate,
  validateSignaturesFromBuffer,
  validatePdfSignatures
};
