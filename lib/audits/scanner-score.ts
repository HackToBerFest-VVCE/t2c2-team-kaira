export type FindingSeverity = "info" | "low" | "medium" | "high";
export type FindingStatus = "pass" | "fail" | "not_applicable";

export interface ScoreFinding {
  id: string;
  pageUrl?: string;
  severity: FindingSeverity;
  status: FindingStatus;
}

export const weights: Record<FindingSeverity, number> = {
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

export function uniqueRuleFindings(findings: ScoreFinding[]) {
  const rules = new Map<string, ScoreFinding>();
  for (const finding of findings) {
    const key = `${finding.id}:${finding.pageUrl ?? "default"}`;
    const existing = rules.get(key);
    if (!existing || (finding.status === "fail" && existing.status !== "fail")) {
      rules.set(key, finding);
    }
  }
  return [...rules.values()];
}

export function sitePageScore(findings: ScoreFinding[]): number {
  const applicable = uniqueRuleFindings(findings).filter(
    (finding) => finding.status !== "not_applicable",
  );

  if (applicable.length === 0) {
    return 100;
  }

  const deductions = applicable.reduce(
    (sum, finding) => sum + (finding.status === "fail" ? weights[finding.severity] : 0),
    0,
  );

  return Math.max(0, 100 - deductions);
}

export function scoreAudit(findings: ScoreFinding[]): number {
  const pages = new Map<string, ScoreFinding[]>();

  for (const finding of findings) {
    const pageKey = finding.pageUrl ?? "default";
    const pageFindings = pages.get(pageKey) ?? [];
    pageFindings.push(finding);
    pages.set(pageKey, pageFindings);
  }

  const pageScores = [...pages.values()].map(sitePageScore);

  if (pageScores.length === 0) {
    return 100;
  }

  return Math.round(
    pageScores.reduce((sum, score) => sum + score, 0) / pageScores.length,
  );
}

export function grade(score: number) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function securityLevel(score: number) {
  if (score >= 90) return { label: "Strong", tone: "good" };
  if (score >= 80) return { label: "Moderate", tone: "warn" };
  if (score >= 60) return { label: "Needs attention", tone: "warn" };
  return { label: "High risk", tone: "bad" };
}

export function calculateScanCoverage({
  pagesScanned,
  pagesFailed,
  pagesOmitted,
}: {
  pagesScanned: number;
  pagesFailed: number;
  pagesOmitted: number;
  pageLimit: number;
}): { percentage: number; label: string; details: string } {
  const totalPages = pagesScanned + pagesFailed + pagesOmitted;
  const percentage = totalPages === 0 ? 0 : Math.round((pagesScanned / totalPages) * 100);

  if (pagesFailed > 0 || pagesOmitted > 0) {
    return {
      percentage,
      label: "Partial coverage",
      details: `${pagesScanned} discovered page(s) scanned · ${pagesFailed} failed · ${pagesOmitted} omitted`,
    };
  }

  return {
    percentage,
    label: pagesScanned === 0 ? "No live pages checked" : "Complete coverage",
    details: `${pagesScanned} discovered page(s) verified.`,
  };
}
