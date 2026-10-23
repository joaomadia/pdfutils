const fs = require("fs");
const path = require("path");

const packagePath = path.join(__dirname, "..", "package.json");
const pkg = JSON.parse(fs.readFileSync(packagePath, "utf8"));
const match = String(pkg.version || "").match(/^(\d+)\.(\d+)\.(\d+)$/);

if (!match) {
  throw new Error(`Versao invalida no package.json: ${pkg.version}`);
}

let [, major, minor, patch] = match.map(Number);
if (patch >= 9) {
  patch = 0;
  if (minor >= 9) {
    minor = 0;
    major += 1;
  } else {
    minor += 1;
  }
} else {
  patch += 1;
}

pkg.version = `${major}.${minor}.${patch}`;
fs.writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");
console.log(pkg.version);
