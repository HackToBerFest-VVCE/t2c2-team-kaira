import type { IncomingHttpHeaders } from "node:http";

export type AuditSeverity = "info" | "low" | "medium" | "high";
export type AuditFindingStatus = "pass" | "fail" | "not_applicable";

export interface AuditFinding {
  id: string;
  severity: AuditSeverity;
  status: AuditFindingStatus;
  title: string;
  explanation: string;
  evidence: string;
  recommendation: string;
}

export interface WebsiteResponseForAudit {
  requestedUrl: string;
  finalUrl: string;
  statusCode: number;
  headers: IncomingHttpHeaders;
}

function getHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(", ");
  return typeof value === "string" ? value : undefined;
}

function headerFinding(
  id: string,
  title: string,
  headerName: string,
  value: string | undefined,
  recommendation: string,
  severity: AuditSeverity,
  options: {
    weak?: (value: string) => boolean;
    weakReason?: string;
    presenceOnly?: boolean;
  } = {},
): AuditFinding {
  if (!value) {
    return {
      id,
      severity,
      status: "fail",
      title,
      explanation: `${headerName} was not present in the final response. Its absence indicates a missing browser-side hardening control; it does not by itself prove an exploitable vulnerability.`,
      evidence: `${headerName}: absent`,
      recommendation,
    };
  }

  const weak = options.weak?.(value) ?? false;
  return {
    id,
    severity: weak ? severity : "info",
    status: weak ? "fail" : "pass",
    title,
    explanation: weak
      ? `${headerName} was present, but ${options.weakReason ?? "its value may provide weaker protection than intended"}.`
      : options.presenceOnly
        ? `${headerName} was present in the final response. This is a presence check only; the policy directives and their effectiveness are not evaluated.`
        : `${headerName} was present in the final response. This check verifies presence and a basic value; it is not a complete policy review.`,
    evidence: `${headerName}: ${value.slice(0, 300)}`,
    recommendation,
  };
}

function hasWeakScriptPolicy(value: string): boolean {
  const directives = value
    .toLowerCase()
    .split(";")
    .map((directive) => directive.trim().split(/\s+/))
    .filter((directive) => directive.length > 0);
  const scriptDirective = directives.find(([name]) => name === "script-src");
  const defaultDirective = directives.find(([name]) => name === "default-src");
  if (!scriptDirective && !defaultDirective) return true;
  const sources = scriptDirective?.slice(1) ?? defaultDirective?.slice(1) ?? [];
  return (
    sources.length === 0 ||
    sources.some((source) => ["*", "'unsafe-inline'", "'unsafe-eval'"].includes(source))
  );
}

function frameAncestorsSources(value: string | undefined): string[] | undefined {
  const directive = value?.split(";").map((item) => item.trim()).find((item) => /^frame-ancestors(?:\s|$)/i.test(item));
  return directive?.split(/\s+/).slice(1);
}

function cookieHeaderValues(headers: IncomingHttpHeaders): string[] {
  const value = headers["set-cookie"];
  if (Array.isArray(value)) return value;
  return typeof value === "string" ? [value] : [];
}

function cookieNames(values: string[]): string[] {
  return values.map((value, index) => {
    const name = value.split(";", 1)[0]?.split("=", 1)[0]?.trim();
    return name || `unnamed-${index + 1}`;
  });
}

function cookieFlagFinding(
  id: string,
  title: string,
  values: string[],
  names: string[],
  flagPattern: RegExp,
  recommendation: string,
  explanationWhenMissing: string,
): AuditFinding {
  if (values.length === 0) {
    return {
      id,
      severity: "info",
      status: "not_applicable",
      title,
      explanation: "The final response did not set cookies, so this flag check is not applicable.",
      evidence: "Set-Cookie: absent",
      recommendation: "No action is needed unless this response begins setting cookies.",
    };
  }

  const missingNames = values.flatMap((value, index) =>
    flagPattern.test(value) ? [] : [names[index]],
  );
  const missing = missingNames.length > 0;

  return {
    id,
    severity: missing ? "low" : "info",
    status: missing ? "fail" : "pass",
    title,
    explanation: missing
      ? explanationWhenMissing
      : `All ${values.length} cookie(s) observed include this flag.`,
    evidence: missing
      ? `Cookies missing this flag: ${missingNames.join(", ")}`
      : `Checked ${values.length} Set-Cookie header(s); values are not included.`,
    recommendation,
  };
}

function cookieFindings(headers: IncomingHttpHeaders): AuditFinding[] {
  const values = cookieHeaderValues(headers);
  const names = cookieNames(values);
  const sameSiteMissingNames = values.flatMap((value, index) => {
    const sameSite = value.match(/(?:^|;)\s*samesite\s*=\s*(strict|lax|none)\s*(?:;|$)/i)?.[1];
    const hasSecure = /(?:^|;)\s*secure\s*(?:;|$)/i.test(value);
    return !sameSite || (sameSite.toLowerCase() === "none" && !hasSecure) ? [names[index]] : [];
  });
  const sameSiteMissing = sameSiteMissingNames.length > 0;

  return [
    cookieFlagFinding(
      "cookies.secure",
      "Cookie Secure flags",
      values,
      names,
      /(?:^|;)\s*secure\s*(?:;|$)/i,
      "Set Secure on cookies that should only be sent over HTTPS.",
      "Secure is absent on one or more cookies. This may expose cookie transmission on non-HTTPS requests; the header alone does not identify whether a cookie is session-sensitive.",
    ),
    cookieFlagFinding(
      "cookies.httponly",
      "Cookie HttpOnly flags",
      values,
      names,
      /(?:^|;)\s*httponly\s*(?:;|$)/i,
      "Set HttpOnly on session and other cookies that do not need JavaScript access.",
      "HttpOnly is absent on one or more cookies. This may be intentional for client-readable cookies, but it allows scripts to read those cookie values if script execution is compromised.",
    ),
    values.length === 0
      ? cookieFlagFinding(
          "cookies.samesite",
          "Cookie SameSite attributes",
          values,
          names,
          /(?:^|;)\s*samesite\s*=\s*(?:strict|lax|none)\s*(?:;|$)/i,
          "Set an explicit SameSite=Lax or SameSite=Strict policy where compatible; SameSite=None also requires Secure.",
          "SameSite is absent or unrecognized on one or more cookies.",
        )
      : {
          id: "cookies.samesite",
          severity: sameSiteMissing ? "low" : "info",
          status: sameSiteMissing ? "fail" : "pass",
          title: "Cookie SameSite attributes",
          explanation: sameSiteMissing
            ? "SameSite is absent or unrecognized on one or more cookies, or SameSite=None is missing Secure. This is a configuration signal rather than proof of a cross-site request vulnerability."
            : `All ${values.length} cookie(s) have a recognized SameSite value, and cookies using None also include Secure.`,
          evidence: sameSiteMissing
            ? `Cookies needing review: ${sameSiteMissingNames.join(", ")}`
            : `Checked ${values.length} Set-Cookie header(s); values are not included.`,
          recommendation: "Set an explicit SameSite=Lax or SameSite=Strict policy where compatible; SameSite=None requires Secure.",
        },
  ];
}

export function auditWebsiteResponse(response: WebsiteResponseForAudit): AuditFinding[] {
  const requestedUrl = new URL(response.requestedUrl);
  const finalUrl = new URL(response.finalUrl);
  const isHttps = requestedUrl.protocol === "https:" && finalUrl.protocol === "https:";
  const csp = getHeader(response.headers, "content-security-policy");
  const xFrameOptions = getHeader(response.headers, "x-frame-options")?.trim().toLowerCase();
  const frameSources = frameAncestorsSources(csp);
  const hasSafeFrameAncestors = Boolean(frameSources?.length && !frameSources.includes("*"));
  const hasWeakFrameAncestors = Boolean(frameSources && !hasSafeFrameAncestors);
  const hasFrameControl = Boolean(
    (xFrameOptions && ["deny", "sameorigin"].includes(xFrameOptions)) || hasSafeFrameAncestors,
  );
  const hsts = getHeader(response.headers, "strict-transport-security");
  const findings: AuditFinding[] = [
    {
      id: "transport.https",
      severity: isHttps ? "info" : "medium",
      status: isHttps ? "pass" : "fail",
      title: "HTTPS transport",
      explanation: isHttps
        ? "The requested URL and final response both use HTTPS. This confirms the URL scheme only; it is not a full TLS configuration assessment."
        : "The requested URL or final response used HTTP. The response may be observable or modifiable in transit; this check does not inspect certificate strength.",
      evidence: `Requested: ${requestedUrl.protocol}//${requestedUrl.host}; final: ${finalUrl.protocol}//${finalUrl.host}`,
      recommendation: "Serve the site over HTTPS and redirect HTTP requests to HTTPS.",
    },
    headerFinding(
      "headers.content-security-policy",
      "Content Security Policy",
      "Content-Security-Policy",
      csp,
      "Define a restrictive policy for trusted script, style, image, and connection sources; avoid unsafe-inline and unsafe-eval where possible.",
      "medium",
      {
        weak: hasWeakScriptPolicy,
        weakReason: "the script policy contains a wildcard, unsafe-inline, or unsafe-eval source",
      },
    ),
    finalUrl.protocol === "https:"
      ? headerFinding(
          "headers.strict-transport-security",
          "Strict Transport Security",
          "Strict-Transport-Security",
          hsts,
          "Set a suitable max-age (commonly at least one year) and consider includeSubDomains after confirming all subdomains support HTTPS.",
          "medium",
          {
            weak: (value) => {
              const maxAge = value.match(/(?:^|;)\s*max-age\s*=\s*(\d+)/i);
              return !maxAge || Number(maxAge[1]) < 15_768_000;
            },
            weakReason: "max-age is missing, invalid, or shorter than six months",
          },
        )
      : {
          id: "headers.strict-transport-security",
          severity: "info",
          status: "not_applicable",
          title: "Strict Transport Security",
          explanation: "The final response used HTTP. Browsers only honor HSTS when received over HTTPS.",
          evidence: `Final URL scheme: ${finalUrl.protocol}`,
          recommendation: "Enable HSTS after the site and relevant subdomains are reliably available over HTTPS.",
        },
    headerFinding(
      "headers.x-content-type-options",
      "MIME type sniffing protection",
      "X-Content-Type-Options",
      getHeader(response.headers, "x-content-type-options"),
      "Return X-Content-Type-Options: nosniff.",
      "low",
      {
        weak: (value) => value.trim().toLowerCase() !== "nosniff",
        weakReason: "the value is not nosniff",
      },
    ),
    {
      id: "headers.frame-options",
      severity: hasFrameControl ? "info" : "medium",
      status: hasFrameControl ? "pass" : "fail",
      title: "Framing protection",
      explanation: hasFrameControl
        ? "A recognized X-Frame-Options or CSP frame-ancestors directive was observed. This basic check does not evaluate every browser or policy interaction."
        : hasWeakFrameAncestors
          ? "CSP frame-ancestors allows any origin with a wildcard or has no allowed source. This broad policy does not provide useful framing restriction."
          : "Neither a recognized X-Frame-Options value nor a restrictive CSP frame-ancestors directive was observed. This is a missing defense signal, not proof that clickjacking is exploitable.",
      evidence: `X-Frame-Options: ${xFrameOptions ?? "absent"}; CSP frame-ancestors: ${frameSources?.join(" ") ?? "absent"}`,
      recommendation: "Set Content-Security-Policy frame-ancestors to the origins that may embed the site; use X-Frame-Options as a compatible fallback.",
    },
    headerFinding(
      "headers.referrer-policy",
      "Referrer policy",
      "Referrer-Policy",
      getHeader(response.headers, "referrer-policy"),
      "Use a deliberate policy such as strict-origin-when-cross-origin or no-referrer.",
      "low",
      {
        weak: (value) => /(?:^|,)\s*(?:unsafe-url|no-referrer-when-downgrade)\s*(?:,|$)/i.test(value),
        weakReason: "the value may disclose full referrer URLs to other origins",
      },
    ),
    headerFinding(
      "headers.permissions-policy",
      "Browser feature policy",
      "Permissions-Policy",
      getHeader(response.headers, "permissions-policy"),
      "Review whether a Permissions-Policy is appropriate and configure its directives for the browser features the site uses.",
      "low",
      { presenceOnly: true },
    ),
    ...cookieFindings(response.headers),
  ];

  return findings;
}