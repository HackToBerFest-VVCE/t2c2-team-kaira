import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const excludedDirectories = new Set([
  ".git",
  "node_modules",
  ".next",
  "build",
  "dist",
  "out",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  "env",
]);

const scannedExtensions = new Set([
  ".cjs",
  ".cfg",
  ".conf",
  ".ini",
  ".js",
  ".jsx",
  ".json",
  ".mjs",
  ".py",
  ".ps1",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
]);

const maximumFiles = 5_000;
const maximumEntries = 20_000;
const maximumFileBytes = 1_000_000;
const maximumTotalBytes = 20_000_000;
const maximumDirectoryDepth = 64;

export type SecretSeverity = "critical" | "high" | "medium";
export type SecretType =
  | "API key"
  | "Password"
  | "Token"
  | "Private key"
  | "Credential";

export type SecretFinding = {
  type: SecretType;
  filePath: string;
  line: number;
  severity: SecretSeverity;
};

export class SecretScanError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "SecretScanError";
    this.status = status;
  }
}

export function validateScanDirectory(projectRoot: string, requestedPath = "") {
  if (
    typeof requestedPath !== "string" ||
    requestedPath.includes("\0") ||
    path.isAbsolute(requestedPath) ||
    path.win32.isAbsolute(requestedPath)
  ) {
    throw new SecretScanError(
      "Scan directory must be a relative path inside the project.",
      400,
    );
  }

  const segments = requestedPath.split(/[\\/]+/);
  if (segments.some((segment) => segment === "..")) {
    throw new SecretScanError(
      "Parent-directory segments are not allowed in scan paths.",
      400,
    );
  }

  const root = path.resolve(projectRoot);
  const target = path.resolve(root, requestedPath || ".");
  const relative = path.relative(root, target);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new SecretScanError(
      "Scan directory must stay inside the project.",
      400,
    );
  }

  return { root, target };
}

function isEnvironmentFile(fileName: string) {
  return /^\.env(?:\.|$)/i.test(fileName) ||
    /(?:^|[.-])env(?:[.-]|$)/i.test(fileName) ||
    /^\.envrc$/i.test(fileName) ||
    /^\.?(?:npmrc|pypirc)$/i.test(fileName);
}

function isScannableFile(fileName: string) {
  return !isEnvironmentFile(fileName) &&
    scannedExtensions.has(path.extname(fileName).toLowerCase());
}

function isPlaceholder(value: string) {
  return /^(?:\*+|x+|changeme|change[_ -]?me|example|placeholder|your[_ -].*|<.*>|\$\{?.+\}?|process\.env\..+|os\.environ(?:\.get)?\(.+\))$/i
    .test(value);
}

type SecretPattern = {
  type: SecretType;
  severity: SecretSeverity;
  expression: RegExp;
};

const secretPatterns: SecretPattern[] = [
  {
    type: "API key",
    severity: "critical",
    expression: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    type: "Token",
    severity: "critical",
    expression: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  },
  {
    type: "Token",
    severity: "high",
    expression: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
  },
  {
    type: "API key",
    severity: "high",
    expression: /\b(?:sk|rk)_live_[A-Za-z0-9]{12,}\b/g,
  },
  {
    type: "API key",
    severity: "high",
    expression: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
  },
  {
    type: "Private key",
    severity: "critical",
    expression: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  {
    type: "API key",
    severity: "high",
    expression: /\b(?:api[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*["'`]([^"'`\s,;]{8,})/gi,
  },
  {
    type: "Password",
    severity: "high",
    expression: /\b(?:password|passwd|pwd)\b["']?\s*[:=]\s*["'`]([^"'`\s,;]{6,})/gi,
  },
  {
    type: "Token",
    severity: "high",
    expression: /\b(?:token|access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token)\b["']?\s*[:=]\s*["'`]([^"'`\s,;]{8,})/gi,
  },
  {
    type: "Credential",
    severity: "high",
    expression: /\b(?:secret|credential)\b["']?\s*[:=]\s*["'`]([^"'`\s,;]{8,})/gi,
  },
];

export function detectSecrets(
  contents: string,
  filePath: string,
  seenSecrets?: Set<string>,
): SecretFinding[] {
  const findings: SecretFinding[] = [];

  contents.split(/\r?\n/).forEach((lineText, index) => {
    for (const pattern of secretPatterns) {
      pattern.expression.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = pattern.expression.exec(lineText)) !== null) {
        const capturedSecret = match[1] ?? match[0];
        if (isPlaceholder(capturedSecret)) continue;

        const fingerprint =
          seenSecrets && pattern.type !== "Private key"
            ? createHash("sha256")
                .update(`${pattern.type}\0${capturedSecret}`)
                .digest("hex")
            : undefined;
        if (fingerprint && seenSecrets?.has(fingerprint)) break;

        if (
          !findings.some(
            (finding) =>
              finding.type === pattern.type && finding.line === index + 1,
          )
        ) {
          findings.push({
            type: pattern.type,
            filePath,
            line: index + 1,
            severity: pattern.severity,
          });
          if (fingerprint) seenSecrets?.add(fingerprint);
        }

        if (match[0].length === 0) pattern.expression.lastIndex += 1;
        break;
      }
    }
  });

  return findings;
}

export async function scanProjectSecrets(
  projectRoot: string,
  requestedPath = "",
) {
  const { root, target } = validateScanDirectory(projectRoot, requestedPath);
  let targetStats;

  try {
    const relativeTarget = path.relative(root, target);
    let cursor = root;
    for (const segment of relativeTarget.split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, segment);
      if ((await fs.lstat(/*turbopackIgnore: true*/ cursor)).isSymbolicLink()) {
        throw new SecretScanError(
          "Symbolic links are not allowed as scan directories.",
          400,
        );
      }
    }
    targetStats = await fs.stat(/*turbopackIgnore: true*/ target);
  } catch (error) {
    if (error instanceof SecretScanError) throw error;
    throw new SecretScanError("The requested scan directory was not found.", 400);
  }

  if (!targetStats.isDirectory()) {
    throw new SecretScanError("The scan path must be a directory.", 400);
  }

  const findings: SecretFinding[] = [];
  let scannedFiles = 0;
  let totalBytes = 0;
  let visitedEntries = 0;

  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > maximumDirectoryDepth) {
      throw new SecretScanError(
        "The project directory tree is too deeply nested to scan.",
        413,
      );
    }

    const entries = await fs.readdir(
      /*turbopackIgnore: true*/ directory,
      { withFileTypes: true },
    );
    visitedEntries += entries.length;
    if (visitedEntries > maximumEntries) {
      throw new SecretScanError(
        "The project contains too many directory entries to scan in one request.",
        413,
      );
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (!excludedDirectories.has(entry.name.toLowerCase())) {
          await walk(path.join(directory, entry.name), depth + 1);
        }
        continue;
      }

      if (!entry.isFile() || !isScannableFile(entry.name)) continue;
      scannedFiles += 1;
      if (scannedFiles > maximumFiles) {
        throw new SecretScanError(
          "The project contains too many files to scan in one request.",
          413,
        );
      }

      const absolutePath = path.resolve(directory, entry.name);
      const relativePath = path.relative(root, absolutePath);
      if (
        relativePath === ".." ||
        relativePath.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relativePath)
      ) {
        throw new SecretScanError(
          "A file path escaped the project scan directory.",
          400,
        );
      }

      const fileStats = await fs.stat(/*turbopackIgnore: true*/ absolutePath);
      if (fileStats.size > maximumFileBytes) continue;
      totalBytes += fileStats.size;
      if (totalBytes > maximumTotalBytes) {
        throw new SecretScanError(
          "The project exceeds the maximum scan size.",
          413,
        );
      }

      const contents = await fs.readFile(
        /*turbopackIgnore: true*/ absolutePath,
        "utf8",
      );
      findings.push(...detectSecrets(contents, relativePath));
    }
  }

  await walk(target, 0);

  return {
    scannedFiles,
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter(({ severity }) => severity === "critical")
        .length,
      high: findings.filter(({ severity }) => severity === "high").length,
      medium: findings.filter(({ severity }) => severity === "medium").length,
    },
  };
}
