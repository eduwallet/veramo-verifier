import { execSync } from "child_process";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

export function getBuildInfo() {
  const { version } = require("../../package.json");

  let commit = null;
  let tag = null;

  try {
    commit = execSync("git rev-parse HEAD").toString().trim();
  } catch { /* empty */ }

  try {
    tag = execSync("git describe --tags --exact-match").toString().trim();
  } catch { /* empty */ }

  return { version, commit, tag: tag || '', node: process.version };
}
