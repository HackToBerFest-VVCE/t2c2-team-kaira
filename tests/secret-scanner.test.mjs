import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  detectSecrets,
  scanProjectSecrets,
  SecretScanError,
  validateScanDirectory,
} from "../lib/audits/secret-scanner.ts";

async function createProject(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "vibe-guard-secrets-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test("detects common secrets without returning matched values", () => {
  const contents = [
    "api_" + 'key = "api-value-that-is-private"',
    "pass" + 'word: "my-hidden-password"',
    "access_" + "token" + ' = "token-value-that-is-private"',
    "-----BEGIN RSA " + "PRIVATE KEY-----",
    'password = "${PASSWORD}"',
  ].join("\n");
  const findings = detectSecrets(contents, "src/settings.py");

  assert.deepEqual(findings.map(({ type, line, severity }) => ({
    type,
    line,
    severity,
  })), [
    { type: "API key", line: 1, severity: "high" },
    { type: "Password", line: 2, severity: "high" },
    { type: "Token", line: 3, severity: "high" },
    { type: "Private key", line: 4, severity: "critical" },
  ]);
  assert.doesNotMatch(JSON.stringify(findings), /api-value|hidden-password|token-value/);
});

test("recognizes provider tokens and JSON credential keys", () => {
  const findings = detectSecrets(
    [
      'const github = "ghp_' + 'abcdefghijklmnopqrstuvwxyz123456";',
      '{"pass' + 'word": "secret-json-password"}',
      'const example = "your_api_key_here";',
    ].join("\n"),
    "app.js",
  );

  assert.deepEqual(findings.map(({ type, line }) => ({ type, line })), [
    { type: "Token", line: 1 },
    { type: "Password", line: 2 },
  ]);
});

test("scans supported source files while excluding environment and build/dependency directories", async (t) => {
  const root = await createProject(t);
  await mkdir(path.join(root, "src"));
  await mkdir(path.join(root, "node_modules", "example"), { recursive: true });
  await mkdir(path.join(root, ".git"));
  await mkdir(path.join(root, "build"), { recursive: true });
  await writeFile(
    path.join(root, "src", "server.py"),
    "pass" + 'word = "super-private-password"',
  );
  await writeFile(
    path.join(root, "src", "app.ts"),
    "const api" + 'Key = "api-secret-value";',
  );
  await writeFile(path.join(root, ".env"), "API_KEY=" + '"env-file-secret-value"');
  await writeFile(
    path.join(root, "node_modules", "example", "index.js"),
    "pass" + 'word = "dependency-secret-value"',
  );
  await writeFile(path.join(root, ".git", "config.js"), "tok" + 'en = "git-secret-value"');
  await writeFile(path.join(root, "build", "output.js"), "tok" + 'en = "build-secret-value"');

  const result = await scanProjectSecrets(root);
  const serialized = JSON.stringify(result);

  assert.equal(result.scannedFiles, 2);
  assert.equal(result.summary.total, 2);
  assert.deepEqual(
    result.findings.map(({ filePath, line, type }) => ({ filePath, line, type })),
    [
      { filePath: path.join("src", "app.ts"), line: 1, type: "API key" },
      { filePath: path.join("src", "server.py"), line: 1, type: "Password" },
    ],
  );
  assert.doesNotMatch(
    serialized,
    /super-private-password|api-secret-value|sk_live_|env-file-secret|dependency-secret|git-secret|build-secret/,
  );
});

test("rejects absolute paths and traversal before scanning", () => {
  for (const requestedPath of [
    "..",
    `src${path.sep}..${path.sep}..`,
    "C:\\outside",
    "\\\\server\\share",
  ]) {
    assert.throws(
      () => validateScanDirectory("C:\\project", requestedPath),
      (error) => error instanceof SecretScanError && error.status === 400,
    );
  }
});

test("scans only the requested in-project directory", async (t) => {
  const root = await createProject(t);
  await mkdir(path.join(root, "src"));
  await mkdir(path.join(root, "docs"));
  await writeFile(path.join(root, "src", "app.js"), "tok" + 'en = "src-token-value"');
  await writeFile(path.join(root, "docs", "example.py"), "pass" + 'word = "doc-password-value"');

  const result = await scanProjectSecrets(root, "src");

  assert.equal(result.scannedFiles, 1);
  assert.deepEqual(result.findings.map(({ filePath }) => filePath), [
    path.join("src", "app.js"),
  ]);
});
