import { NextResponse } from "next/server";
import path from "node:path";
import fs from "node:fs/promises";
import {
  DependencyAuditError,
  formatDependencyFindings,
  runDependencyAudit,
} from "../../../../lib/audits/dependency-audit.ts";

export async function POST() {
  try {
    const projectRoot = process.cwd();
    await fs.access(path.join(projectRoot, "package.json"));

    const report = await runDependencyAudit(projectRoot);
    const summary = report.metadata?.vulnerabilities ?? {};

    return NextResponse.json({
      project: path.basename(projectRoot),
      scannedAt: new Date().toISOString(),
      summary: {
        total: summary.total ?? 0,
        info: summary.info ?? 0,
        critical: summary.critical ?? 0,
        high: summary.high ?? 0,
        moderate: summary.moderate ?? 0,
        low: summary.low ?? 0,
      },
      findings: formatDependencyFindings(report.vulnerabilities ?? {}),
    });
  } catch (error) {
    const auditError = error instanceof DependencyAuditError
      ? error
      : new DependencyAuditError(
          error instanceof Error
            ? error.message
            : "Dependency scan failed unexpectedly.",
          500,
        );

    console.error("Dependency audit failed:", error);

    return NextResponse.json(
      { error: auditError.message },
      { status: auditError.status },
    );
  }
}
