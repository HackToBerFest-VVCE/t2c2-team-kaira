export interface ComparableAuditFinding {
  id: string;
  pageUrl: string;
  status: "pass" | "fail" | "not_applicable";
  title: string;
}

export function compareAuditFindings(
  previousUrl: string,
  latestUrl: string,
  previousFindings: ComparableAuditFinding[],
  latestFindings: ComparableAuditFinding[],
) {
  let previousOrigin: string;
  let latestOrigin: string;
  try {
    previousOrigin = new URL(previousUrl).origin;
    latestOrigin = new URL(latestUrl).origin;
  } catch {
    return null;
  }
  if (previousOrigin !== latestOrigin) return null;

  const keyOf = (finding: ComparableAuditFinding) => {
    let pathname = finding.pageUrl;
    try {
      pathname = new URL(finding.pageUrl).pathname;
    } catch {
      // Retain the supplied resource key if a test or older report lacks an absolute URL.
    }
    return `${finding.id}:${pathname}`;
  };
  const latest = new Map(latestFindings.map((finding) => [keyOf(finding), finding]));
  const previousFailureKeys = new Set(
    previousFindings.filter((finding) => finding.status === "fail").map(keyOf),
  );
  const latestFailureKeys = new Set(
    latestFindings.filter((finding) => finding.status === "fail").map(keyOf),
  );
  const resolved: ComparableAuditFinding[] = [];
  const persisting: ComparableAuditFinding[] = [];
  const newFindings: ComparableAuditFinding[] = [];

  for (const key of previousFailureKeys) {
    const current = latest.get(key);
    if (!current) continue;
    if (latestFailureKeys.has(key)) persisting.push(current);
    else resolved.push(current);
  }
  for (const [key, finding] of latest) {
    if (latestFailureKeys.has(key) && !previousFailureKeys.has(key)) {
      newFindings.push(finding);
    }
  }

  return { resolved, persisting, newFindings };
}
