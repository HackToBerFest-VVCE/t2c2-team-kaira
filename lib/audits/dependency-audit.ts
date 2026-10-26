import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const auditTimeoutMs = 60_000;
const maxAuditOutputBytes = 10 * 1024 * 1024;

export type AuditCommandResult = {
  stdout?: string;
  stderr?: string;
  code?: string | number;
  killed?: boolean;
  signal?: string;
  message?: string;
};

type NpmFix = {
  name?: string;
  version?: string;
  isSemVerMajor?: boolean;
};

type NpmAuditFinding = {
  severity?: string;
  isDirect?: boolean;
  range?: string;
  fixAvailable?: boolean | NpmFix;
  via?: unknown[];
};

type NpmAuditReport = {
  error?: {
    code?: string;
    summary?: string;
    detail?: string;
  };
  metadata?: {
    vulnerabilities?: {
      total?: number;
      info?: number;
      low?: number;
      moderate?: number;
      high?: number;
      critical?: number;
    };
  };
  vulnerabilities?: Record<string, NpmAuditFinding>;
};

export class DependencyAuditError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "DependencyAuditError";
    this.status = status;
  }
}

function isAuditTimeout(error: AuditCommandResult) {
  return Boolean(
    error.killed ||
    error.signal === "SIGTERM" ||
    String(error.code ?? "").toUpperCase() === "ETIMEDOUT",
  );
}

function isNetworkFailure(error: AuditCommandResult) {
  const detail = error.stderr?.trim() || error.message?.trim();
  const errorCode = String(error.code ?? "").toUpperCase();

  return /ENOTFOUND|EAI_AGAIN|ECONNRESET|ECONNREFUSED|ETIMEDOUT|network|fetch failed/i
    .test(`${errorCode} ${detail ?? ""}`);
}

export function classifyNpmCommandError(error: AuditCommandResult) {
  const detail = error.stderr?.trim() || error.message?.trim();
  const errorCode = String(error.code ?? "").toUpperCase();

  if (isAuditTimeout(error)) {
    return new DependencyAuditError(
      "Dependency scan timed out while waiting for npm audit.",
      504,
    );
  }

  if (isNetworkFailure(error)) {
    return new DependencyAuditError(
      "npm could not reach the package registry. Check the network connection and try again.",
      502,
    );
  }

  if (errorCode === "ENOENT") {
    return new DependencyAuditError(
      "npm was not found on the server. Install Node.js/npm and restart the application.",
      500,
    );
  }

  return new DependencyAuditError(
    detail || "Could not run npm audit.",
    500,
  );
}

export function parseNpmAuditReport(stdout: string): NpmAuditReport {
  let report: unknown;

  try {
    report = JSON.parse(stdout);
  } catch {
    throw new DependencyAuditError(
      "npm did not return valid audit JSON.",
      502,
    );
  }

  if (typeof report !== "object" || report === null || Array.isArray(report)) {
    throw new DependencyAuditError(
      "npm returned an unexpected audit response.",
      502,
    );
  }

  const result = report as NpmAuditReport;

  if (result.error) {
    const summary = result.error.summary || "npm audit failed.";
    const detail = result.error.detail;
    const errorCode = result.error.code?.toUpperCase() ?? "";

    if (
      /ENOTFOUND|EAI_AGAIN|ECONNRESET|ECONNREFUSED|ETIMEDOUT|network|fetch failed/i
        .test(`${errorCode} ${summary} ${detail ?? ""}`)
    ) {
      throw new DependencyAuditError(
        "npm could not reach the package registry. Check the network connection and try again.",
        502,
      );
    }

    throw new DependencyAuditError(
      [summary, detail].filter(Boolean).join(" "),
      500,
    );
  }

  if (!result.metadata?.vulnerabilities || !result.vulnerabilities) {
    throw new DependencyAuditError(
      "npm returned an incomplete audit report.",
      502,
    );
  }

  return result;
}

export async function runDependencyAudit(projectRoot: string) {
  let stdout = "";

  try {
    const command = process.platform === "win32" ? "cmd.exe" : "npm";
    const args = process.platform === "win32"
      ? ["/d", "/s", "/c", "npm.cmd audit --json --omit=dev"]
      : ["audit", "--json", "--omit=dev"];
    const result = await execFileAsync(command, args, {
      cwd: projectRoot,
      timeout: auditTimeoutMs,
      maxBuffer: maxAuditOutputBytes,
      windowsHide: true,
    });
    stdout = result.stdout;
  } catch (error) {
    const commandError = error as AuditCommandResult;
    stdout = commandError.stdout ?? "";

    if (isAuditTimeout(commandError) || isNetworkFailure(commandError)) {
      throw classifyNpmCommandError(commandError);
    }

    if (!stdout.trim()) {
      throw classifyNpmCommandError(commandError);
    }
  }

  return parseNpmAuditReport(stdout);
}

export function formatDependencyFindings(
  vulnerabilities: Record<string, NpmAuditFinding>,
) {
  return Object.entries(vulnerabilities).map(([name, item]) => {
    const fix = typeof item.fixAvailable === "object"
      ? item.fixAvailable
      : undefined;

    return {
      package: name,
      severity: item.severity ?? "unknown",
      direct: item.isDirect ?? false,
      affectedRange: item.range ?? "",
      fixAvailable: Boolean(item.fixAvailable),
      fix: fix
        ? {
            name: fix.name,
            version: fix.version,
            isSemVerMajor: fix.isSemVerMajor,
          }
        : null,
      advisory: (item.via ?? [])
        .filter(
          (entry): entry is { title?: string; url?: string } =>
            typeof entry === "object" && entry !== null,
        )
        .map((entry) => ({
          title: entry.title,
          url: entry.url,
        })),
    };
  });
}
