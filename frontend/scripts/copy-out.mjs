// Copies the static export (out/) into backend/static, which FastAPI serves at "/".
import { cpSync, existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "out");
const target = join(root, "..", "backend", "static");
if (!existsSync(join(out, "index.html"))) throw new Error("out/index.html missing: run next build first");
rmSync(target, { recursive: true, force: true });
cpSync(out, target, { recursive: true });
console.log(`copied ${out} -> ${target}`);
