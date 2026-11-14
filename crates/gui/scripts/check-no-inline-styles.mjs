import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distDir = path.join(rootDir, "dist");

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(full)));
    } else {
      files.push(full);
    }
  }
  return files;
}

const files = await walk(distDir);
const violations = [];

for (const file of files) {
  const ext = path.extname(file);
  if (ext !== ".html" && ext !== ".js") {
    continue;
  }
  const content = await readFile(file, "utf8");
  if (ext === ".html") {
    if (/<style\b/i.test(content)) {
      violations.push(`${path.relative(rootDir, file)}: contains <style> tag`);
    }
    if (/\sstyle\s*=/i.test(content)) {
      violations.push(`${path.relative(rootDir, file)}: contains style= attribute`);
    }
  }
  if (ext === ".js") {
    if (/<style\b/i.test(content) || /\sstyle\s*=/i.test(content)) {
      violations.push(`${path.relative(rootDir, file)}: embeds inline style markup`);
    }
    if (/\.style\s*[.=]/.test(content) || /setAttribute\(\s*["']style["']/.test(content)) {
      violations.push(`${path.relative(rootDir, file)}: mutates inline style at runtime`);
    }
    if (/innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(/.test(content)) {
      violations.push(`${path.relative(rootDir, file)}: uses unsafe HTML sink`);
    }
  }
}

if (violations.length > 0) {
  console.error("CSP / Safe-DOM violations detected:\n" + violations.join("\n"));
  process.exit(1);
}

console.log(`CSP & Safe-DOM check passed (${files.length} dist artifacts scanned).`);
