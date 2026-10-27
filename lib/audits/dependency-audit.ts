import { execFile } from "node:child_process";
import fs from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
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
  nodes?: string[];
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function getDependencySnapshot(projectRoot: string) {
  const packageJsonPath = path.join(projectRoot, "package.json");
  const lockfileCandidates = [
    path.join(projectRoot, "package-lock.json"),
    path.join(projectRoot, "npm-shrinkwrap.json"),
  ];

  const packageJsonExists = fs.existsSync(packageJsonPath);
  const lockfilePath = lockfileCandidates
    .find((candidate) => fs.existsSync(candidate));

  return {
    packageJsonExists,
    lockfilePath,
    packageJsonPath,
  };
}

export function validateDependencyProject(packageJsonText: string, lockfileText: string) {
  let manifest: unknown;
  let lockfile: unknown;
  try {
    manifest = JSON.parse(packageJsonText);
    lockfile = JSON.parse(lockfileText);
  } catch {
    throw new DependencyAuditError("Dependency data unavailable: invalid JSON in package manifest or lockfile.", 400);
  }

  if (!isRecord(manifest) || !isRecord(lockfile)) {
    throw new DependencyAuditError("Dependency data unavailable: invalid package manifest or lockfile.", 400);
  }

  const parsedLockfile = lockfile as {
    lockfileVersion?: unknown;
    packages?: unknown;
    dependencies?: unknown;
  };
  const packages = isRecord(parsedLockfile.packages) ? parsedLockfile.packages : null;
  const dependencies = isRecord(parsedLockfile.dependencies) ? parsedLockfile.dependencies : null;
  if (
    !Number.isInteger(parsedLockfile.lockfileVersion) ||
    ![1, 2, 3].includes(parsedLockfile.lockfileVersion as number) ||
    (!packages && !dependencies)
  ) {
    throw new DependencyAuditError("Dependency data unavailable: unsupported or incomplete lockfile.", 400);
  }

  const lockedPackages = new Set<string>();
  const packageNameFromLockPath = (packagePath: string) => {
    const segments = packagePath.split("node_modules/").at(-1)?.split("/") ?? [];
    return segments[0]?.startsWith("@") ? segments.slice(0, 2).join("/") : segments[0];
  };
  for (const packagePath of Object.keys(packages ?? {})) {
    const packageName = packageNameFromLockPath(packagePath);
    if (packageName) lockedPackages.add(packageName);
  }
  const visitLegacyDependencies = (entries: Record<string, unknown>) => {
    for (const [name, entry] of Object.entries(entries)) {
      if (!isRecord(entry)) continue;
      lockedPackages.add(name);
      if (isRecord(entry.dependencies)) visitLegacyDependencies(entry.dependencies);
    }
  };
  if (dependencies) visitLegacyDependencies(dependencies);

  const manifestDependencies = [
    isRecord(manifest.dependencies) ? Object.keys(manifest.dependencies) : [],
    isRecord(manifest.optionalDependencies) ? Object.keys(manifest.optionalDependencies) : [],
  ].flat();
  const missingDependencies = manifestDependencies.filter((name) => !lockedPackages.has(name));
  if (missingDependencies.length > 0) {
    throw new DependencyAuditError(
      `Dependency data unavailable: lockfile is missing declared package(s): ${missingDependencies.join(", ")}.`,
      400,
    );
  }

  const parsedManifest = manifest as { name?: unknown };
  return {
    name: typeof parsedManifest.name === "string" && /^[a-zA-Z0-9._-]{1,100}$/.test(parsedManifest.name)
      ? parsedManifest.name
      : "uploaded-project",
  };
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

function advisoryEntries(via: unknown[] | undefined) {
  return (via ?? [])
    .filter(
      (entry): entry is { title?: string; url?: string; source?: string | number; severity?: string } =>
        typeof entry === "object" && entry !== null,
    )
    .map((entry) => ({
      title: entry.title,
      url: entry.url,
      source: entry.source === undefined ? undefined : String(entry.source),
      severity: entry.severity,
    }));
}

function extractVulnerabilityId(via: unknown[] | undefined, packageName: string) {
  const advisory = advisoryEntries(via).find((entry) => Boolean(entry.source || entry.url || entry.title));
  if (advisory?.source) return advisory.source;
  if (advisory?.url) return new URL(advisory.url).pathname.split("/").filter(Boolean).at(-1) ?? packageName;
  if (advisory?.title) return advisory.title;
  return packageName;
}

function readPackageLockVersions(packageLockPath: string | undefined) {
  if (!packageLockPath || !fs.existsSync(packageLockPath)) {
    return new Map<string, string>();
  }

  try {
    const raw = fs.readFileSync(packageLockPath, "utf8");
    const parsed = JSON.parse(raw);
    const versions = new Map<string, Set<string>>();

    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const packages = parsed.packages && typeof parsed.packages === "object" ? parsed.packages : {};
      for (const [packagePath, info] of Object.entries(packages)) {
        if (!packagePath || !info || typeof info !== "object") continue;
        const segments = packagePath.split("node_modules/").at(-1)?.split("/") ?? [];
        const packageName = segments[0]?.startsWith("@")
          ? segments.slice(0, 2).join("/")
          : segments[0];
        if (packageName && typeof (info as { version?: string }).version === "string") {
          const packageVersions = versions.get(packageName) ?? new Set<string>();
          packageVersions.add((info as { version: string }).version);
          versions.set(packageName, packageVersions);
        }
      }

      const addLegacyDependencyVersions = (dependencies: unknown) => {
        if (typeof dependencies !== "object" || dependencies === null || Array.isArray(dependencies)) return;
        for (const [name, info] of Object.entries(dependencies)) {
          if (typeof info !== "object" || info === null || Array.isArray(info)) continue;
          const dependency = info as { version?: unknown; dependencies?: unknown };
          if (typeof dependency.version === "string") {
            const packageVersions = versions.get(name) ?? new Set<string>();
            packageVersions.add(dependency.version);
            versions.set(name, packageVersions);
          }
          addLegacyDependencyVersions(dependency.dependencies);
        }
      };
      addLegacyDependencyVersions(parsed.dependencies);
    }

    return new Map([...versions].map(([name, values]) => [name, [...values]]));
  } catch {
    return new Map<string, string[]>();
  }
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
  const snapshot = getDependencySnapshot(projectRoot);
  if (!snapshot.packageJsonExists) {
    throw new DependencyAuditError("Dependency data unavailable", 404);
  }

  if (!snapshot.lockfilePath) {
    throw new DependencyAuditError("Dependency data unavailable", 404);
  }

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

export async function runDependencyAuditForFiles(
  packageJsonText: string,
  lockfileText: string,
) {
  const project = validateDependencyProject(packageJsonText, lockfileText);
  const projectRoot = await mkdtemp(path.join(os.tmpdir(), "vibe-guard-deps-"));
  try {
    await Promise.all([
      writeFile(path.join(projectRoot, "package.json"), packageJsonText, { flag: "wx" }),
      writeFile(path.join(projectRoot, "package-lock.json"), lockfileText, { flag: "wx" }),
    ]);
    const report = await runDependencyAudit(projectRoot);
    return {
      project: project.name,
      report,
      findings: formatDependencyFindings(report.vulnerabilities ?? {}, projectRoot),
    };
  } finally {
    await rm(projectRoot, { recursive: true, force: true });
  }
}

export function formatDependencyFindings(
  vulnerabilities: Record<string, NpmAuditFinding>,
  projectRoot?: string,
) {
  const lockfilePath = projectRoot ? getDependencySnapshot(projectRoot).lockfilePath : undefined;
  const installedVersions = readPackageLockVersions(lockfilePath);

  return Object.entries(vulnerabilities).map(([name, item]) => {
    const fix = typeof item.fixAvailable === "object"
      ? item.fixAvailable
      : undefined;
    const advisory = advisoryEntries(item.via);

    return {
      package: name,
      installedVersion: installedVersions.get(name) ?? [],
      locations: (item.nodes ?? []).filter((node) => typeof node === "string"),
      vulnerabilityId: extractVulnerabilityId(item.via, name),
      severity: item.severity ?? "unknown",
      direct: item.isDirect ?? false,
      affectedRange: item.range ?? "",
      fixAvailable: Boolean(item.fixAvailable),
      recommendedVersion: fix?.version ?? "not available",
      fix: fix
        ? {
            name: fix.name,
            version: fix.version,
            isSemVerMajor: fix.isSemVerMajor,
          }
        : null,
      advisory: advisory.map((entry) => ({
        title: entry.title,
        url: entry.url,
        source: entry.source,
        severity: entry.severity,
      })),
    };
  });
}
