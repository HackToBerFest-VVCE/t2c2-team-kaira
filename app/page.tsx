
"use client";

import { useState, type FormEvent } from "react";
import { compareAuditFindings } from "../lib/audits/audit-comparison.ts";
import {
  calculateScanCoverage,
  grade,
  scoreAudit,
  securityLevel,
} from "../lib/audits/scanner-score.ts";

type FindingStatus = "pass" | "fail" | "not_applicable";
type FindingSeverity = "info" | "low" | "medium" | "high";

interface AuditFinding {
  id: string;
  pageUrl: string;
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
  scanMode: string;
  pageLimit: number;
  pagesScanned: number;
  pagesFailed: number;
  pagesOmitted: number;
  scannedAt: string;
  findings: AuditFinding[];
}

interface SecretFinding {
  type: string;
  resource: string;
  line: number;
  severity: "critical" | "high" | "medium";
}

interface SecretCheck {
  resource: string;
  kind: "HTML" | "JavaScript";
  status: "scanned" | "failed" | "skipped" | "omitted" | "external";
  count?: number;
  httpStatus?: number;
  message?: string;
}

interface SecretScanResult {
  scannedAt: string;
  target: string;
  pagesScanned: number;
  pagesFailed: number;
  resourcesScanned: number;
  resourcesFailed: number;
  resourcesSkipped: number;
  resourcesOmitted: number;
  resourcesExternal: number;
  complete: boolean;
  status?: "completed" | "partial" | "timed_out";
  checks: SecretCheck[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
  };
  findings: SecretFinding[];
}


function category(id: string) {
  if (id.startsWith("transport.")) return "Transport";
  if (id.startsWith("cookies.")) return "Cookies";
  if (id.startsWith("response.")) return "Response";
  if (id.startsWith("content.")) return "Page content";
  return "Headers";
}

function priority(severity: FindingSeverity) {
  return { high: 3, medium: 2, low: 1, info: 0 }[severity];
}

function uniqueRuleFindings(findings: AuditFinding[]) {
  const rules = new Map<string, AuditFinding>();
  for (const finding of findings) {
    const existing = rules.get(finding.id);
    if (!existing || (finding.status === "fail" && existing.status !== "fail")) {
      rules.set(finding.id, finding);
    }
  }
  return [...rules.values()];
}

function findingKey(finding: AuditFinding) {
  return `${finding.id}:${finding.pageUrl}`;
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
  
const [secretScan, setSecretScan] = useState<SecretScanResult | null>(null);
const [secretLoading, setSecretLoading] = useState(false);
const [secretError, setSecretError] = useState("");


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
  
async function scanSecrets() {
  setSecretLoading(true);
  setSecretError("");

  try {
    if (!url.trim()) {
      throw new Error("Enter the website URL above before scanning for exposed secrets.");
    }

    let normalizedUrl = url.trim();
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    const response = await fetch("/api/audits/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: normalizedUrl }),
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(
        payload.status === "timed_out"
          ? `${payload.error || "The resource request timed out."} The root page was not scanned; try again later.`
          : payload.error || "Secret scan failed.",
      );
    }

    setSecretScan(payload as SecretScanResult);
  } catch (err) {
    setSecretError(
      err instanceof Error ? err.message : "Secret scan failed.",
    );
  } finally {
    setSecretLoading(false);
  }
}


  const findings = audit?.findings ?? [];
  const score = scoreAudit(findings);
  const ruleFindings = uniqueRuleFindings(findings);
  const coverage = audit
    ? calculateScanCoverage({
        pagesScanned: audit.pagesScanned,
        pagesFailed: audit.pagesFailed,
        pagesOmitted: audit.pagesOmitted,
        pageLimit: audit.pageLimit,
      })
    : null;
  const siteSecurityLevel = audit ? securityLevel(score) : null;
  const comparison = previousAudit && audit
    ? compareAuditFindings(previousAudit.finalUrl, audit.finalUrl, previousAudit.findings, findings)
    : null;
  const failed = ruleFindings.filter((f) => f.status === "fail");
  const passed = ruleFindings.filter((f) => f.status === "pass");
  const notApplicable = ruleFindings.filter(
    (f) => f.status === "not_applicable",
  );

  const topFixes = [...failed]
    .sort((a, b) => priority(b.severity) - priority(a.severity))
    .slice(0, 3);

  const groups = ["Transport", "Response", "Page content", "Headers", "Cookies"];

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
          <div className="vg-logo">Q</div>
          <div>
            <strong>QUALYS</strong>
            <span>SECURITY WORKSPACE</span>
          </div>
        </div>

        <div className="vg-side-label">WORKSPACE</div>
        <a className="vg-nav active" href="#overview">▦ Overview</a>
        <a className="vg-nav" href="#findings">⌕ Findings</a>
        <a className="vg-nav" href="#fixes">✳ Priority fixes</a>
        <a className="vg-nav" href="#secrets">🔐 Secrets</a>
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
            <div className="vg-eyebrow">QUALYS / SECURITY CENTER</div>
            <h1>Security overview</h1>
            <p>Find configuration risks before they reach production.</p>
          </div>
          <span className="vg-live"><span className="vg-dot" /> SCANNER ONLINE</span>
        </header>

        <section className="vg-scan-panel">
          <div>
            <div className="vg-eyebrow">NEW WEBSITE AUDIT</div>
            <h2>Scan your website</h2>
            <p>Fetches the live site and checks HTTP responses, page content, headers, and cookies.</p>
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
                {loading ? "Scanning…" : "↗ Scan Website"}
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
                  <p>
                    {audit.pagesScanned} page(s) scanned
                    {audit.pagesFailed ? ` · ${audit.pagesFailed} same-origin page(s) could not be scanned` : ""}
                    {audit.pagesOmitted ? ` · ${audit.pagesOmitted} additional page(s) omitted by the scan limit` : ""}
                    {" · "}{new Date(audit.scannedAt).toLocaleString()}
                  </p>
                </div>
                <button className="vg-secondary-button" onClick={downloadReport}>
                  ↓ Download report
                </button>
              </div>

              <div className="vg-overview-grid">
                <article className="vg-card vg-score-card">
                  <div className="vg-card-label">VERIFIED CHECK SCORE</div>
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
                  <div className="vg-grade">CHECK GRADE {grade(score)}</div>
                  <p>Weighted only from observed applicable checks. This is not an overall security rating.</p>
                  <div className="vg-grade-scale">Security level: {siteSecurityLevel?.label ?? "Not available"}</div>
                </article>

                <article className="vg-card vg-gate-card">
                  <div className="vg-card-label">PASSIVE CHECK STATUS</div>
                  <div className={`vg-gate-status ${failed.length ? "blocked" : "approved"}`}>
                    <span>{failed.length ? "⊘" : "✓"}</span>
                    <strong>{failed.length ? "REVIEW FINDINGS" : "NO FAILURES OBSERVED"}</strong>
                  </div>
                  <p>
                    {failed.length
                      ? `${failed.length} observed check(s) failed.`
                      : "No failures were observed in the checks completed by this scan."}
                  </p>
                  <div className="vg-note">This is not deployment approval or a complete vulnerability assessment. Live, passive HTTP and page-content checks only; no login or exploit testing.</div>
                </article>

                <article className="vg-card vg-summary-card">
                  <div className="vg-card-label">SCAN SUMMARY</div>
                  <div className="vg-stat"><span className="vg-status-dot pass" /> Passed <strong>{passed.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot fail" /> Needs attention <strong>{failed.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot na" /> Not applicable <strong>{notApplicable.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot info" /> Total checks <strong>{ruleFindings.length}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot info" /> Pages scanned <strong>{audit.pagesScanned}</strong></div>
                  <div className="vg-stat"><span className="vg-status-dot info" /> Security level <strong>{siteSecurityLevel?.label ?? "Unrated"}</strong></div>
                </article>
                <article className="vg-card">
                  <div className="vg-card-label">SCAN COVERAGE</div>
                  <h2>{coverage?.percentage ?? 0}%</h2>
                  <p>{coverage?.label ?? "Not available"} · {coverage?.details ?? "No page scan data."}</p>
                  <p>Coverage is the portion of discovered pages scanned; scan limits and failed pages are shown separately.</p>
                </article>
              </div>
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
                      <article className="vg-finding" key={findingKey(finding)}>
                        <button
                          className="vg-finding-toggle"
                          onClick={() => toggleFinding(findingKey(finding))}
                          aria-expanded={expanded.includes(findingKey(finding))}
                        >
                          <span className={`vg-status-dot ${finding.status === "pass" ? "pass" : finding.status === "fail" ? "fail" : "na"}`} />
                          <span className="vg-finding-title">{finding.title}</span>
                          <span className={`vg-severity ${finding.severity}`}>{finding.severity}</span>
                          <span className={`vg-status-pill ${finding.status}`}>{finding.status.replace("_", " ")}</span>
                          <span className="vg-chevron">{expanded.includes(findingKey(finding)) ? "−" : "+"}</span>
                        </button>
                        {expanded.includes(findingKey(finding)) && (
                          <div className="vg-finding-detail">
                            <div className="vg-detail-label">SCANNED PAGE</div>
                            <p>{new URL(finding.pageUrl).pathname}</p>
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
                {previousAudit && comparison ? (
                  <>
                    <div><span>Previous score</span><strong>{scoreAudit(previousAudit.findings)}/100</strong><small>{previousAudit.target}</small></div>
                    <div><span>Latest score</span><strong>{score}/100</strong><small>{audit.target}</small></div>
                    <div><span>Score change</span><strong className={score >= scoreAudit(previousAudit.findings) ? "vg-positive" : "vg-negative"}>{score - scoreAudit(previousAudit.findings) > 0 ? "+" : ""}{score - scoreAudit(previousAudit.findings)}</strong><small>Points</small></div>
                  </>
                ) : previousAudit ? (
                  <p>Comparison is unavailable because these scans are for different websites. Scan the same website before and after the change.</p>
                ) : (
                  <p>Run another scan in this session to compare it with this result. Previous scans are not stored permanently yet.</p>
                )}
              </div>
              {previousAudit && comparison && (
                <div className="vg-card vg-history-bars">
                  <div className="vg-card-label">SCORE COMPARISON</div>
                  {[{ label: "Previous", value: scoreAudit(previousAudit.findings) }, { label: "Latest", value: score }].map((item) => (
                    <div className="vg-bar-row" key={item.label}>
                      <span>{item.label}</span>
                      <div className="vg-bar-track"><div className="vg-bar-fill" style={{ width: `${item.value}%` }} /></div>
                      <strong>{item.value}</strong>
                    </div>
                  ))}
                  <div className="vg-card-label">CHECK CHANGES ON THE SAME WEBSITE</div>
                  <p>{comparison.resolved.length} resolved · {comparison.persisting.length} still failing · {comparison.newFindings.length} newly failing</p>
                  {[...comparison.resolved.map((item) => ({ ...item, change: "Resolved" })),
                    ...comparison.persisting.map((item) => ({ ...item, change: "Still failing" })),
                    ...comparison.newFindings.map((item) => ({ ...item, change: "New failure" }))].map((item) => (
                    <p key={`${item.change}:${item.id}:${item.pageUrl}`}>
                      {item.change}: {item.title} ({new URL(item.pageUrl).pathname})
                    </p>
                  ))}
                </div>
              )}
            </section>

            <section className="vg-section">
              <div className="vg-section-heading">
                <div>
                  <div className="vg-eyebrow">SCAN COVERAGE</div>
                  <h2>What this run verified</h2>
                </div>
                <span className="vg-count">LIVE RESULTS</span>
              </div>
              <div className="vg-card vg-timeline">
                {[
                  ["01", "Live pages scanned", `${audit.pagesScanned} page(s) scanned; ${audit.pagesFailed} failed; ${audit.pagesOmitted} omitted by scan limits.`, true],
                  ["02", "Observed checks evaluated", `${findings.length} page-level results across ${ruleFindings.length} distinct checks.`, true],
                  ["03", "Security level", `${siteSecurityLevel?.label ?? "Unrated"} (score ${score}/100)`, true],
                  ["04", "Coverage for this run", `${coverage?.label ?? "Unknown"} (${coverage?.percentage ?? 0}%)`, true],
                  ["05", "Accuracy validation", "Measured only by labeled regression tests; not a real-world detection accuracy claim.", false],
                  ["06", "Automated remediation", "Not performed by this passive scanner.", false],
                  ["07", "Exploit verification", "Not performed; active testing is outside this scan.", false],
                ].map(([number, title, description, complete]) => (
                  <div className="vg-timeline-step" key={String(number)}>
                    <span className={`vg-timeline-number ${complete ? "complete" : ""}`}>{complete ? "✓" : number}</span>
                    <div><strong>{String(title)}</strong><p>{String(description)}</p></div>
                    <span className={`vg-timeline-state ${complete ? "complete" : ""}`}>{complete ? "AVAILABLE" : "NOT CONNECTED"}</span>
                  </div>
                ))}
              </div>
              <p className="vg-footnote">Security score reflects weighted observed check results; coverage separately reflects pages scanned, failed, and omitted. Accuracy is tested against labeled regression fixtures only; no real-world accuracy percentage is asserted. Results do not cover authenticated pages, backend source, or all vulnerability classes.</p>
            </section>
          </>
        )}

        <section id="secrets" className="vg-section">
          <div className="vg-section-heading">
            <div>
              <div className="vg-eyebrow">SECRET DETECTION</div>
              <h2>Exposed credentials</h2>
              <p>Inspect the submitted site’s publicly served HTML and same-origin JavaScript.</p>
            </div>
            <button
              className="vg-secondary-button"
              onClick={scanSecrets}
              disabled={secretLoading}
            >
              {secretLoading ? "Scanning..." : "Scan for secrets"}
            </button>
          </div>

          {secretError && <p className="vg-error" role="alert">{secretError}</p>}

          {secretScan && (
            <>
              <div className="vg-overview-grid">
                <article className="vg-card">
                  <div className="vg-card-label">SECRETS FOUND</div>
                  <h2>{secretScan.summary.total}</h2>
                  <p>Pattern matches in publicly served site responses.</p>
                </article>
                <article className="vg-card">
                  <div className="vg-card-label">CRITICAL / HIGH</div>
                  <h2>{secretScan.summary.critical + secretScan.summary.high}</h2>
                  <p>Findings requiring priority review.</p>
                </article>
                <article className="vg-card">
                  <div className="vg-card-label">RESOURCE COVERAGE</div>
                  <h2>{secretScan.resourcesScanned}</h2>
                  <p>
                    {secretScan.resourcesFailed} failed · {secretScan.resourcesSkipped} skipped
                    <br />
                    {secretScan.resourcesOmitted} omitted by limits
                    <br />
                    {secretScan.pagesScanned} HTML page(s) scanned
                    {secretScan.resourcesExternal > 0
                      ? ` · ${secretScan.resourcesExternal} external script(s) not fetched`
                      : ""}
                  </p>
                </article>
              </div>
              <p className={secretScan.complete ? "vg-success-message" : "vg-error"} role={secretScan.complete ? undefined : "alert"}>
                {secretScan.complete
                  ? `All discovered same-origin resources within the scan limits were checked.${secretScan.resourcesExternal > 0 ? ` ${secretScan.resourcesExternal} external script(s) were excluded and not fetched.` : ""}`
                  : `${secretScan.status === "timed_out" ? "Scan timed out. " : "Scan incomplete. "}${secretScan.resourcesFailed} resource(s) failed, ${secretScan.resourcesSkipped} were skipped, and ${secretScan.resourcesOmitted} were omitted by scan limits. ${secretScan.pagesFailed} HTML page(s) failed. Review resource statuses and reasons below.`}
              </p>
              <div className="vg-priority-list">
                {secretScan.findings.length === 0 ? (
                  <p className={secretScan.complete ? "vg-success-message" : "vg-note"}>
                    {secretScan.complete
                      ? "No matching exposed-secret patterns were detected in the resources that were scanned. This does not prove the site has no secrets."
                      : "No matching exposed-secret patterns were detected in the resources scanned so far. This scan is incomplete and is not a clean result."}
                  </p>
                ) : (
                  secretScan.findings.map((finding, index) => (
                    <article className="vg-priority-item" key={`${finding.resource}:${finding.line}:${index}`}>
                      <div className="vg-priority-content">
                        <strong>{finding.type}</strong>
                        <p>{finding.resource}:{finding.line}</p>
                        <p>Matched pattern found in publicly served content. Secret value is withheld.</p>
                      </div>
                      <span className={`vg-severity ${finding.severity === "critical" || finding.severity === "high" ? "high" : "medium"}`}>
                        {finding.severity}
                      </span>
                    </article>
                  ))
                )}
              </div>
              <div className="vg-priority-list">
                {secretScan.checks.map((check, index) => (
                  <article className="vg-priority-item" key={`${check.resource}:${check.kind}:${index}`}>
                    <div className="vg-priority-content">
                      <strong>{check.kind}: {check.resource}</strong>
                      <p>
                        {check.status}
                        {check.count ? ` · ${check.count} resources` : ""}
                        {check.httpStatus ? ` · HTTP ${check.httpStatus}` : ""}
                        {check.message ? ` · ${check.message}` : ""}
                      </p>
                    </div>
                    <span className={`vg-severity ${check.status === "scanned" ? "low" : "medium"}`}>
                      {check.status}
                    </span>
                  </article>
                ))}
              </div>
              <p className="vg-footnote">
                Public responses only; server-side source, authenticated resources, and secrets not matching scanner patterns are not covered. Secret values are never included. Scanned{" "}
                {new Date(secretScan.scannedAt).toLocaleString()}.
              </p>
            </>
          )}
        </section>

        <footer className="vg-footer">QUALYS · SECURITY WITH CLARITY</footer>
      </section>
    </main>
  );
}
