import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { extname, join } from "node:path";

const cwd = process.cwd();

// tsc's output already exists at this point; make the CLI entrypoint
// executable. No-op (not an error) on platforms/filesystems without exec
// bits (e.g. some Windows filesystems) - npm's own bin-linking is what
// actually matters for `rig` on PATH.
try {
  chmodSync(join(cwd, "dist", "bin-wrapper.js"), 0o755);
} catch {
  // best-effort; see comment above
}

function copyByExt(sourceDir, targetDir, ext) {
  mkdirSync(targetDir, { recursive: true });
  if (!existsSync(sourceDir)) return;
  for (const entry of readdirSync(sourceDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    if (extname(entry.name).toLowerCase() !== ext) continue;
    copyFileSync(join(sourceDir, entry.name), join(targetDir, entry.name));
  }
}

copyByExt(join(cwd, "src", "schemas"), join(cwd, "dist", "schemas"), ".json");
copyByExt(join(cwd, "src", "lib", "scope-templates"), join(cwd, "dist", "lib", "scope-templates"), ".md");
copyFileSync(join(cwd, "..", "..", "LICENSE"), join(cwd, "LICENSE"));
