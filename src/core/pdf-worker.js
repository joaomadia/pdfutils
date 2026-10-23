const pdf = require("./pdf");

async function runTask(message) {
  const progress = (text, percent = 0) => {
    if (typeof process.send === "function") {
      process.send({ type: "progress", message: text || "", percent: Number(percent) || 0 });
    }
  };

  const task = message?.task || "";
  const payload = message?.payload || message || {};

  if (task === "convert") {
    return await pdf.convertAnyFileToPdfA(payload, (text, pct) => progress(text, pct));
  }

  if (task === "prepare-signature") {
    return await pdf.preparePdfAForSigning(payload, (text, pct) => progress(text, pct));
  }

  if (task === "merge") {
    return await pdf.mergeFilesToPdf(payload, (text, pct) => progress(text, pct));
  }

  // Comportamento padrão: conversão para PDF/A
  return await pdf.convertAnyFileToPdfA(payload, (text, pct) => progress(text, pct));
}

process.on("message", async (message) => {
  try {
    const result = await runTask(message);
    if (typeof process.send === "function") {
      process.send({ type: "result", result });
    }
  } catch (error) {
    if (typeof process.send === "function") {
      process.send({
        type: "error",
        error: {
          message: error?.message || "Erro desconhecido no worker de PDF.",
          stack: error?.stack || ""
        }
      });
    }
  }
});