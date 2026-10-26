
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

const statusLabels: Record<FindingStatus, string> = {
  pass: "Passed",
  fail: "Needs attention",
  not_applicable: "Not applicable",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAuditFinding(value: unknown): value is AuditFinding {
  if (!isRecord(value)) return false;

  return (
    typeof value.id === "string" &&
    typeof value.title === "string" &&
    typeof value.explanation === "string" &&
    typeof value.evidence === "string" &&
    typeof value.recommendation === "string" &&
    ["info", "low", "medium", "high"].includes(String(value.severity)) &&
    ["pass", "fail", "not_applicable"].includes(String(value.status))
  );
}

function isAuditResult(value: unknown): value is AuditResult {
  return (
    isRecord(value) &&
    typeof value.target === "string" &&
    typeof value.finalTarget === "string" &&
    typeof value.requestedUrl === "string" &&
    typeof value.finalUrl === "string" &&
    typeof value.redirected === "boolean" &&
    typeof value.queryChanged === "boolean" &&
    typeof value.statusCode === "number" &&
    typeof value.scannedAt === "string" &&
    Array.isArray(value.findings) &&
    value.findings.every(isAuditFinding)
  );
}

function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("Enter a website URL to start an audit.");
  if (trimmed.length > 2048) throw new Error("The URL must be 2,048 characters or fewer.");

  const scheme = trimmed.match(/^([a-z][a-z\d+.-]*):/i)?.[1].toLowerCase();
  const looksLikeHostPort = /^[^/?#]+:\d+(?:[/?#]|$)/.test(trimmed);
  if (scheme && !looksLikeHostPort && !["http", "https"].includes(scheme)) {
    throw new Error("Use an HTTP or HTTPS website URL.");
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(
      scheme === "http" || scheme === "https" ? trimmed : `https://${trimmed}`,
    );
  } catch {
    throw new Error("Enter a valid URL, such as https://your-website.com.");
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol) || !parsedUrl.hostname) {
    throw new Error("Use an HTTP or HTTPS website URL.");
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error("URLs containing a username or password are not allowed.");
  }
  if (parsedUrl.port) {
    throw new Error("Only standard HTTP and HTTPS ports can be scanned.");
  }

  return parsedUrl.toString();
}

function apiErrorMessage(payload: unknown, status: number): string {
  if (
    isRecord(payload) &&
    isRecord(payload.error) &&
    typeof payload.error.message === "string"
  ) {
    return payload.error.message;
  }
  return `The audit request failed (HTTP ${status}). Please try again.`;
}

function statusClass(status: FindingStatus): string {
  return `finding-card finding-card--${status}`;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [audit, setAudit] = useState<AuditResult | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setAudit(null);

    let normalizedUrl: string;
    try {
      normalizedUrl = normalizeUrl(url);
    } catch (validationError) {
      setError(
        validationError instanceof Error
          ? validationError.message
          : "Enter a valid website URL.",
      );
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch("/api/audits", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalizedUrl }),
      });
      const payload: unknown = await response.json().catch(() => null);

      if (!response.ok) {
        throw new Error(apiErrorMessage(payload, response.status));
      }
      if (!isAuditResult(payload)) {
        throw new Error("The audit service returned an unexpected response. Please try again.");
      }

      setAudit(payload);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "The audit could not be completed. Check your connection and try again.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  const passedCount = audit?.findings.filter(({ status }) => status === "pass").length ?? 0;
  const failedCount = audit?.findings.filter(({ status }) => status === "fail").length ?? 0;
  const notApplicableCount =
    audit?.findings.filter(({ status }) => status === "not_applicable").length ?? 0;

  return (
    <main className="dashboard-shell">
      <header className="topbar">
        <a className="brand" href="#home" aria-label="Kaira home">
          <span className="brand-mark" aria-hidden="true">K</span>
          <span className="brand-name">kaira</span>
        </a>
        <div className="topbar-note">
          <span className="online-indicator" aria-hidden="true" />
          <span>Website security audits</span>
        </div>
      </header>

      <div className="dashboard-content" id="home">
        <section className="intro-section" aria-labelledby="page-title">
          <div className="intro-copy">
            <p className="eyebrow"><span>01</span> Security workspace</p>
            <h1 id="page-title">A clearer view of your website security.</h1>
            <p className="intro-description">
              Check publicly reachable websites for common transport, header, and cookie
              security configuration issues, with practical next steps.
            </p>
          </div>
          <div className="scope-note">
            <span className="scope-note-label">Scan scope</span>
            <p>Only scan websites you own or have permission to assess.</p>
          </div>
        </section>

        <section className="scan-panel" id="scan" aria-labelledby="scan-title">
          <div className="panel-heading">
            <div>
              <p className="panel-kicker">New assessment</p>
              <h2 id="scan-title">Scan a website</h2>
            </div>
            <span className="method-label">HTTP / HTTPS</span>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <label className="field-label" htmlFor="website-url">Website URL</label>
            <div className="scan-controls">
              <div className="url-field-wrap">
                <span className="url-prefix" aria-hidden="true">↗</span>
                <input
                  id="website-url"
                  name="url"
                  type="text"
                  inputMode="url"
                  autoComplete="url"
                  maxLength={2048}
                  placeholder="https://your-website.com"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  aria-invalid={Boolean(error)}
                  aria-describedby={error ? "scan-message" : "scan-help"}
                  disabled={isLoading}
                />
              </div>
              <button className="scan-button" type="submit" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <span className="loading-spinner" aria-hidden="true" />
                    Scanning
                  </>
                ) : (
                  <>
                    Scan Website
                    <span aria-hidden="true">→</span>
                  </>
                )}
              </button>
            </div>
            <p
              className={`form-message${error ? " form-message--error" : ""}`}
              id={error ? "scan-message" : "scan-help"}
              role={error ? "alert" : undefined}
              aria-live={error ? "assertive" : "polite"}
            >
              {error ?? "A basic configuration review runs against the site’s final response."}
            </p>
          </form>
        </section>

        {isLoading && (
          <div className="loading-message" role="status" aria-live="polite">
            <span className="loading-spinner loading-spinner--large" aria-hidden="true" />
            <div>
              <strong>Reviewing website configuration</strong>
              <p>This can take a few seconds while the site responds.</p>
            </div>
          </div>
        )}

        {audit && (
          <section className="results-section" id="findings" aria-labelledby="results-title">
            <div className="results-header">
              <div>
                <p className="panel-kicker">Assessment complete</p>
                <h2 id="results-title">Findings</h2>
                <p className="results-target">
                  <strong>Requested URL:</strong> {audit.requestedUrl}
                  <br />
                  <strong>Final response URL:</strong> {audit.finalUrl}
                  {audit.redirected && <span> (redirected)</span>}
                  {audit.queryChanged && <span> Query parameters changed; values are hidden.</span>}
                </p>
              </div>
              <p className="scan-time">
                Response {audit.statusCode} · {new Date(audit.scannedAt).toLocaleString()}
              </p>
            </div>

            <div className="summary-strip" aria-label="Finding totals">
              <div className="summary-item summary-item--fail">
                <span className="summary-count">{failedCount}</span>
                <span>Needs attention</span>
              </div>
              <div className="summary-item summary-item--pass">
                <span className="summary-count">{passedCount}</span>
                <span>Passed</span>
              </div>
              <div className="summary-item summary-item--na">
                <span className="summary-count">{notApplicableCount}</span>
                <span>Not applicable</span>
              </div>
            </div>

            <div className="findings-grid">
              {audit.findings.map((finding) => (
                <article className={statusClass(finding.status)} key={finding.id}>
                  <div className="finding-heading">
                    <div className="finding-title-group">
                      <span className={`status-mark status-mark--${finding.status}`} aria-hidden="true">
                        {finding.status === "pass" ? "✓" : finding.status === "fail" ? "!" : "–"}
                      </span>
                      <h3>{finding.title}</h3>
                    </div>
                    <div className="finding-tags">
                      <span className={`status-tag status-tag--${finding.status}`}>
                        {statusLabels[finding.status]}
                      </span>
                      <span className={`severity-tag severity-tag--${finding.severity}`}>
                        {finding.severity} severity
                      </span>
                    </div>
                  </div>
                  <p className="finding-explanation">{finding.explanation}</p>
                  <div className="finding-detail">
                    <span className="detail-label">Evidence</span>
                    <p>{finding.evidence}</p>
                  </div>
                  <div className="finding-detail finding-recommendation">
                    <span className="detail-label">Recommendation</span>
                    <p>{finding.recommendation}</p>
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        <footer className="dashboard-footer">
          <span>Kaira</span>
          <p>Configuration signals are guidance, not proof of exploitability.</p>
        </footer>
      </div>
    </main>
  );
}
