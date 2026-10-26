
import { NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs/promises";

const execFileAsync = promisify(execFile);

export async function POST() {
  try {
    const projectRoot = process.cwd();
    await fs.access(path.join(projectRoot, "package.json"));

    let stdout = "";

    try {
      const result = await execFileAsync(
        process.platform === "win32" ? "cmd.exe" : "npm",
        process.platform === "win32"
          ? ["/d", "/s", "/c", "npm audit --json --omit=dev"]
          : ["audit", "--json", "--omit=dev"],
        {
          cwd: projectRoot,
          timeout: 60000,
          maxBuffer: 10 * 1024 * 1024,
          windowsHide: true,
        }
      );

      stdout = result.stdout;
    } catch (error: unknown) {
      const err = error as {
        stdout?: string;
        stderr?: string;
        message?: string;
      };

      // npm audit exits with a non-zero code when vulnerabilities are found.
      // Its stdout can still contain a valid audit report.
      stdout = err.stdout ?? "";

      if (!stdout.trim()) {
        console.error("Dependency audit process error:", err);
        throw new Error(err.stderr || err.message || "Could not run npm audit.");
      }
    }

    let report;

    try {
      report = JSON.parse(stdout);
    } catch {
      console.error("Invalid npm audit output:", stdout.slice(0, 1000));
      throw new Error("npm did not return valid audit JSON.");
    }

    const summary = report.metadata?.vulnerabilities ?? {};
    const vulnerabilities = report.vulnerabilities ?? {};

    return NextResponse.json({
      project: path.basename(projectRoot),
      scannedAt: new Date().toISOString(),
      summary: {
        total: summary.total ?? 0,
        critical: summary.critical ?? 0,
        high: summary.high ?? 0,
        moderate: summary.moderate ?? 0,
        low: summary.low ?? 0,
      },
      findings: Object.entries(vulnerabilities).map(
        ([name, value]) => {
          const item = value as {
            severity?: string;
            isDirect?: boolean;
            range?: string;
            fixAvailable?: unknown;
            via?: unknown[];
          };

          return {
            package: name,
            severity: item.severity ?? "unknown",
            direct: item.isDirect ?? false,
            affectedRange: item.range ?? "",
            fixAvailable: Boolean(item.fixAvailable),
            advisory: (item.via ?? [])
              .filter(
                (
                  entry
                ): entry is { title?: string; url?: string } =>
                  typeof entry === "object" && entry !== null
              )
              .map((entry) => ({
                title: entry.title,
                url: entry.url,
              })),
          };
        }
      ),
    });
  } catch (error) {
    console.error("Dependency audit failed:", error);

    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Dependency scan failed unexpectedly.",
      },
      { status: 500 }
    );
  }
}
