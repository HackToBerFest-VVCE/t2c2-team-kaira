
"use client";

import { useState, type FormEvent } from "react";

type FindingStatus = "pass" | "fail" | "not_applicable";
type FindingSeverity = "info" | "low" | "medium" | "high";

interface AuditFinding {
  id: string;
  severity: FindingSeverity;
  status: FindingStatus;
  title: string;
  explanation: string;
  evidence: string;
  recommendation: string;
}

interface AuditResult {
  target: string;
  finalTarget: string;
  requestedUrl: string;
  finalUrl: string;
  redirected: boolean;
  queryChanged: boolean;
  statusCode: number;
  scannedAt: string;
  findings: AuditFinding[];
}

interface DependencyFinding {
  package: string;
  severity: string;
  direct: boolean;
  affectedRange: string;
  fixAvailable: boolean;
  advisory: { title?: string; url?: string }[];
}

interface DependencyResult {
  project: string;
  scannedAt: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    moderate: number;
    low: number;
  };
  findings: DependencyFinding[];
}


const weights: Record<FindingSeverity, number> = {
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

function scoreAudit(findings: AuditFinding[]) {
  const applicable = findings.filter(
    (f) => f.status !== "not_applicable",
  );

  const deductions = applicable.reduce(
    (sum, f) =>
      sum + (f.status === "fail" ? weights[f.severity] : 0),
    0,
  );

  return Math.max(0, 100 - deductions);
}

function grade(score: number) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function category(id: string) {
  if (id.startsWith("transport.")) return "Transport";
  if (id.startsWith("cookies.")) return "Cookies";
  return "Headers";
}

function priority(severity: FindingSeverity) {
  return { high: 3, medium: 2, low: 1, info: 0 }[severity];
}

function escapeCsv(value: string) {
  return `"${value.replace(/"/g, '""')}"`;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [previousAudit, setPreviousAudit] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string[]>([]);
  
const [dependencyScan, setDependencyScan] =
  useState<DependencyResult | null>(null);
const [dependencyLoading, setDependencyLoading] = useState(false);
const [dependencyError, setDependencyError] = useState("");


  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      let normalizedUrl = url.trim();
      if (!/^https?:\/\//i.test(normalizedUrl)) {
        normalizedUrl = `https://${normalizedUrl}`;
      }

      const parsed = new URL(normalizedUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Enter a valid HTTP or HTTPS website URL.");
      }

      const response = await fetch("/api/audits", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: parsed.href }),
      });

      const payload = await response.json();

      if (!response.ok) {
        throw new Error(
          payload?.error?.message || "The scan could not be completed.",
        );
      }

      if (!Array.isArray(payload.findings)) {
        throw new Error("The scanner returned an unexpected result.");
      }

      if (audit) setPreviousAudit(audit);
      setAudit(payload as AuditResult);
      setExpanded([]);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Something went wrong.",
      );
    } finally {
      setLoading(false);
    }
  }
  
async function scanDependencies() {
  setDependencyLoading(true);
  setDependencyError("");

  try {
    const response = await fetch("/api/audits/dependencies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Dependency scan failed.");
    }

    setDependencyScan(payload as DependencyResult);
  } catch (err) {
    setDependencyError(
      err instanceof Error ? err.message : "Dependency scan failed.",
    );
  } finally {
    setDependencyLoading(false);
  }
}


  const findings = audit?.findings ?? [];
  const score = scoreAudit(findings);
  const failed = findings.filter((f) => f.status === "fail");
  const passed = findings.filter((f) => f.status === "pass");
  const notApplicable = findings.filter(
    (f) => f.status === "not_applicable",
  );

  const topFixes = [...failed]
    .sort((a, b) => priority(b.severity) - priority(a.severity))
    .slice(0, 3);

  const groups = ["Transport", "Headers", "Cookies"];

  function downloadReport() {
    if (!audit) return;

    const rows = [
      ["Vibe Guard Scan Report"],
      ["Target", audit.target],
      ["Final URL", audit.finalUrl],
      ["Scanned at", audit.scannedAt],
      ["Configuration score", `${score}/100`],
      ["Grade", grade(score)],
      ["Deployment gate", failed.length ? "BLOCKED" : "APPROVED"],
      [],
      ["Category", "Finding", "Severity", "Status", "Evidence", "Recommendation"],
      ...findings.map((f) => [
        category(f.id),
        f.title,
        f.severity,
        f.status,
        f.evidence,
        f.recommendation,
      ]),
    ];

    const csv = rows
      .map((row) => row.map((cell) => escapeCsv(String(cell ?? ""))).join(","))
      .join("\r\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const objectUrl = URL.createObjectURL(blob);
    link.href = objectUrl;
    link.download = "vibe-guard-scan-report.csv";
    link.click();
    URL.revokeObjectURL(objectUrl);
  }

  function toggleFinding(id: string) {
    setExpanded((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id],
    );
  }

  return (
    <main className="vg-app">
      <aside className="vg-sidebar">
        <div className="vg-brand">
          <div className="vg-logo">V</div>
          <div>
            <strong>VIBE GUARD</strong>
            <span>SECURITY WORKSPACE</span>
          </div>
        </div>

        <div className="vg-side-label">WORKSPACE</div>
        <a className="vg-nav active" href="#overview">▦ Overview</a>
        <a className="vg-nav" href="#findings">⌕ Findings</a>
        <a className="vg-nav" href="#fixes">✳ Priority fixes</a>
        <a className="vg-nav" href="#dependencies">⬡ Dependencies</a>
        <a className="vg-nav" href="#history">◷ Scan history</a>

        <div className="vg-sidebar-bottom">
          <span className="vg-dot" />
          <div>
            <strong>Scanner status</strong>
            <span>Ready to scan</span>
          </div>
        </div>
      </aside>

      <section className="vg-main">
        <header className="vg-topbar">
          <div>
            <div className="vg-eyebrow">TEAM KAIRA / SECURITY CENTER</div>
            <h1>Security overview</h1>
            <p>Find configuration risks before they reach production.</p>
          </div>
          <span className="vg-live"><span className="vg-dot" /> SCANNER ONLINE</span>
        </header>

        <section className="vg-scan-panel">
          <div>
            <div className="vg-eyebrow">NEW WEBSITE AUDIT</div>
            <h2>Scan your website</h2>
            <p>Check HTTPS, browser security headers and cookie settings.</p>
          </div>

          <form className="vg-scan-form" onSubmit={handleSubmit}>
            <label htmlFor="target-url">Website URL</label>
            <div className="vg-input-row">
              <input
                id="target-url"
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                required
              />
              <button type="submit" disabled={loading}>
                {loading ? "Scanning…" : "↗ Run scan"}
              </button>
            </div>
          </form>
          {error && <p className="vg-error" role="alert">{error}</p>}
        </section>

        {!audit ? (
          <section className="vg-empty">
            <div className="vg-empty-icon">⌕</div>
            <h2>Your security dashboard is ready</h2>
            <p>Enter a website URL above to see real findings, a configuration score and recommended fixes.</p>
          </section>
        ) : (
          <>
            <section id="overview" className="vg-section">
              <div className="vg-section-heading">
                <div>
                  <div className="vg-eyebrow">LATEST SCAN</div>
                  <h2>{audit.target}</h2>
                  <p>Scanned {new Date(audit.scannedAt).toLocaleString()}</p>
                </div>
                <button className="vg-secondary-button" onClick={downloadReport}>
                  ↓ Download report
                </button>
              </div>

              <div className="vg-overview-grid">
                <article className="vg-card vg-score-card">
                  <div className="vg-card-label">CONFIGURATION SCORE</div>
                  <div
                    className={`vg-gauge ${score >= 80 ? "good" : score >= 60 ? "warn" : "bad"}`}
                    style={{ "--score": `${score * 3.6}deg` } as React.CSSProperties}
                    role="img"
                    aria-label={`Configuration score ${score} out of 100`}
                  >
                    <div className="vg-gauge-inner">
                      <strong>{score}</strong>
                      <span>/ 100</span>
                    </div>
                  </div>
                  <div className="vg-grade">GRADE {grade(score)}</div>
                  <p>Weighted score based on failed applicable checks.</p>
                  <div className="vg-grade-scale">A: 90+ · B: 80+ · C: 70+ · D: 60+ · F: below 60</div>
                </article>

                <article className="vg-card vg-gate-card">
                  <div className="vg-card-label">DEPLOYMENT GATE</div>
                  <div className={`vg-gate-status ${failed.length ? "blocked" : "approved"}`}>
                    <span>{failed.length ? "⊘" : "✓"}</span>
                    <strong>{failed.length ? "BLOCKED" : "APPROVED"}</strong>
                  </div>
                  <p>
                    {failed.length
                      ? `${failed.length} failed check(s) need attention before approval.`
                      : "No failed checks were found in this scan."}
                  </p>
                  <div className="vg-note">Website configuration scan only; this is not a source-code deployment verification.</div>
                </article>

                <article className="vg-card vg-summary-card">
                  <div className="vg-card-label">SCAN SUMMARY</div>
                  <div className="vg-stat"><span className="vg-status-dot pass" /> Passed <strong>{passed.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot fail" /> Needs attention <strong>{failed.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot na" /> Not applicable <strong>{notApplicable.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot info" /> Total checks <strong>{findings.length}</strong></div>
                </article>
              </div>
            </section>
            
<section id="dependencies" className="vg-section">
  <div className="vg-section-heading">
    <div>
      <div className="vg-eyebrow">DEPENDENCY SECURITY</div>
      <h2>Vulnerable packages</h2>
      <p>Check production dependencies for known vulnerabilities.</p>
    </div>

    <button
      className="vg-secondary-button"
      onClick={scanDependencies}
      disabled={dependencyLoading}
    >
      {dependencyLoading ? "Scanning..." : "Scan dependencies"}
    </button>
  </div>

  {dependencyError && (
    <p className="vg-error" role="alert">{dependencyError}</p>
  )}

  {dependencyScan && (
    <>
      <div className="vg-overview-grid">
        <article className="vg-card">
          <div className="vg-card-label">VULNERABILITIES FOUND</div>
          <h2>{dependencyScan.summary.total}</h2>
          <p>Known production dependency vulnerabilities.</p>
        </article>

        <article className="vg-card">
          <div className="vg-card-label">CRITICAL / HIGH</div>
          <h2>
            {dependencyScan.summary.critical +
              dependencyScan.summary.high}
          </h2>
          <p>Issues requiring priority review.</p>
        </article>

        <article className="vg-card">
          <div className="vg-card-label">SCAN STATUS</div>
          <h2>
            {dependencyScan.summary.total === 0
              ? "No issues found"
              : "Review required"}
          </h2>
          <p>
            Scanned{" "}
            {new Date(dependencyScan.scannedAt).toLocaleString()}
          </p>
        </article>
      </div>

      <div className="vg-priority-list">
        {dependencyScan.findings.length === 0 ? (
          <p className="vg-success-message">
            No known production dependency vulnerabilities were reported.
          </p>
        ) : (
          dependencyScan.findings.map((finding) => (
            <article
              className="vg-priority-item"
              key={finding.package}
            >
              <div className="vg-priority-content">
                <strong>{finding.package}</strong>

                <p>
                  Severity: {finding.severity} · Affected range:{" "}
                  {finding.affectedRange || "Not specified"}
                </p>

                <p>
                  {finding.fixAvailable
                    ? "A fix may be available. Review before updating."
                    : "No automatic fix is indicated by the audit result."}
                </p>

                {finding.advisory.map((item, index) => (
                  <p key={`${finding.package}-${index}`}>
                    {item.title || "Security advisory"}
                    {item.url && (
                      <>
                        {" — "}
                        <a
                          href={item.url}
                          target="_blank"
                          rel="noreferrer"
                        >
                          View advisory
                        </a>
                      </>
                    )}
                  </p>
                ))}
              </div>

              <span
                className={`vg-severity ${
                  ["critical", "high"].includes(
                    finding.severity.toLowerCase()
                  )
                    ? "high"
                    : finding.severity.toLowerCase() === "moderate"
                      ? "medium"
                      : "low"
                }`}
              >
                {finding.severity}
              </span>
            </article>
          ))
        )}
      </div>
    </>
  )}
</section>


            <section id="fixes" className="vg-section">
              <div className="vg-section-heading">
                <div>
                  <div className="vg-eyebrow">RECOMMENDED ACTIONS</div>
                  <h2>Top priority fixes</h2>
                </div>
                <span className="vg-count">{topFixes.length} ACTIONS</span>
              </div>

              <div className="vg-priority-list">
                {topFixes.length ? topFixes.map((finding, index) => (
                  <article className="vg-priority-item" key={finding.id}>
                    <span className="vg-priority-number">0{index + 1}</span>
                    <div className="vg-priority-content">
                      <strong>{finding.title}</strong>
                      <p>{finding.recommendation}</p>
                    </div>
                    <span className={`vg-severity ${finding.severity}`}>{finding.severity}</span>
                  </article>
                )) : (
                  <p className="vg-success-message">No failed checks. Keep reviewing future scans.</p>
                )}
              </div>
            </section>

            <section id="findings" className="vg-section">
              <div className="vg-section-heading">
                <div>
                  <div className="vg-eyebrow">SCAN DETAILS</div>
                  <h2>Security findings</h2>
                  <p>Expand a check to see evidence and its recommended fix.</p>
                </div>
              </div>

              {groups.map((group) => {
                const groupFindings = findings.filter((f) => category(f.id) === group);
                if (!groupFindings.length) return null;

                return (
                  <div className="vg-finding-group" key={group}>
                    <h3>{group} <span>{groupFindings.length} checks</span></h3>
                    {groupFindings.map((finding) => (
                      <article className="vg-finding" key={finding.id}>
                        <button
                          className="vg-finding-toggle"
                          onClick={() => toggleFinding(finding.id)}
                          aria-expanded={expanded.includes(finding.id)}
                        >
                          <span className={`vg-status-dot ${finding.status === "pass" ? "pass" : finding.status === "fail" ? "fail" : "na"}`} />
                          <span className="vg-finding-title">{finding.title}</span>
                          <span className={`vg-severity ${finding.severity}`}>{finding.severity}</span>
                          <span className={`vg-status-pill ${finding.status}`}>{finding.status.replace("_", " ")}</span>
                          <span className="vg-chevron">{expanded.includes(finding.id) ? "−" : "+"}</span>
                        </button>
                        {expanded.includes(finding.id) && (
                          <div className="vg-finding-detail">
                            <p>{finding.explanation}</p>
                            <div className="vg-detail-label">EVIDENCE</div>
                            <pre>{finding.evidence}</pre>
                            <div className="vg-detail-label">RECOMMENDED FIX</div>
                            <p>{finding.recommendation}</p>
                            <div className="vg-detail-label">CHECK ID</div>
                            <code>{finding.id}</code>
                          </div>
                        )}
                      </article>
                    ))}
                  </div>
                );
              })}
            </section>

            <section id="history" className="vg-section">
              <div className="vg-section-heading">
                <div>
                  <div className="vg-eyebrow">SCAN COMPARISON</div>
                  <h2>Before & after</h2>
                </div>
              </div>
              <div className="vg-card vg-comparison">
                {previousAudit ? (
                  <>
                    <div><span>Previous score</span><strong>{scoreAudit(previousAudit.findings)}/100</strong><small>{previousAudit.target}</small></div>
                    <div><span>Latest score</span><strong>{score}/100</strong><small>{audit.target}</small></div>
                    <div><span>Score change</span><strong className={score >= scoreAudit(previousAudit.findings) ? "vg-positive" : "vg-negative"}>{score - scoreAudit(previousAudit.findings) > 0 ? "+" : ""}{score - scoreAudit(previousAudit.findings)}</strong><small>Points</small></div>
                  </>
                ) : (
                  <p>Run another scan in this session to compare it with this result. Previous scans are not stored permanently yet.</p>
                )}
              </div>
              {previousAudit && (
                <div className="vg-card vg-history-bars">
                  <div className="vg-card-label">SCORE COMPARISON</div>
                  {[{ label: "Previous", value: scoreAudit(previousAudit.findings) }, { label: "Latest", value: score }].map((item) => (
                    <div className="vg-bar-row" key={item.label}>
                      <span>{item.label}</span>
                      <div className="vg-bar-track"><div className="vg-bar-fill" style={{ width: `${item.value}%` }} /></div>
                      <strong>{item.value}</strong>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="vg-section">
              <div className="vg-section-heading">
                <div>
                  <div className="vg-eyebrow">AUTOMATION STATUS</div>
                  <h2>AI fix & verify timeline</h2>
                </div>
                <span className="vg-count">PLANNED</span>
              </div>
              <div className="vg-card vg-timeline">
                {[
                  ["01", "Finding detected", "Real scan results are available.", true],
                  ["02", "Fix proposed", "AI patch generation is not connected yet.", false],
                  ["03", "Tests executed", "Automated patch tests are not connected yet.", false],
                  ["04", "Rescan verified", "Patch verification is not connected yet.", false],
                ].map(([number, title, description, complete]) => (
                  <div className="vg-timeline-step" key={String(number)}>
                    <span className={`vg-timeline-number ${complete ? "complete" : ""}`}>{complete ? "✓" : number}</span>
                    <div><strong>{String(title)}</strong><p>{String(description)}</p></div>
                    <span className={`vg-timeline-state ${complete ? "complete" : ""}`}>{complete ? "AVAILABLE" : "NOT CONNECTED"}</span>
                  </div>
                ))}
              </div>
              <p className="vg-footnote">This dashboard reports website response checks. It does not currently scan source files, apply code patches, or verify a deployment.</p>
            </section>
          </>
        )}

        <footer className="vg-footer">VIBE GUARD · TEAM KAIRA · SECURITY WITH CLARITY</footer>
      </section>
    </main>
  );
}

