const fs = require("fs");
const path = require("path");

exports.default = async function afterAllArtifactBuild(context) {
  const outputDir = context.outDir || path.join(__dirname, "..", "dist");
  const { version } = require("../package.json");
  const versionedName = `PDFUtils-Setup-${version}.exe`;
  const versionedPath = path.join(outputDir, versionedName);
  const globalPath = path.join(outputDir, "PDFUtils-Setup.exe");

  if (fs.existsSync(versionedPath)) {
    fs.copyFileSync(versionedPath, globalPath);
    return [globalPath];
  }

  return [];
};
