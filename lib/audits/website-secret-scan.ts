import {
  createSafeFetcher,
  safeFetchPublicUrl,
  type SafeFetchResult,
} from "./url-safety.ts";
import { detectSecrets } from "./secret-scanner.ts";
import { SecretScanError } from "./secret-scanner.ts";

const MAX_HTML_PAGES = 5;
const MAX_SCRIPT_FILES = 10;
const MAX_HTML_LINKS_PER_PAGE = 50;
const MAX_SCRIPT_LINKS_PER_PAGE = 50;
const fetchWebsiteResource = createSafeFetcher({ sameOriginRedirectsOnly: true });

type SecretCheck = {
  resource: string;
  kind: "HTML" | "JavaScript";
  status: "scanned" | "failed" | "skipped" | "omitted" | "external";
  count?: number;
  httpStatus?: number;
  message?: string;
};

type WebsiteSecretFinding = {
  type: string;
  resource: string;
  line: number;
  severity: "critical" | "high" | "medium";
};

function resourcePath(input: string, baseUrl: string, origin: string) {
  let parsed: URL;
  try {
    parsed = new URL(input, baseUrl);
  } catch {
    return null;
  }

  if (
    parsed.origin !== origin ||
    parsed.username ||
    parsed.password ||
    !["http:", "https:"].includes(parsed.protocol)
  ) {
    return null;
  }

  parsed.hash = "";
  return parsed;
}

function htmlLinks(html: string, pageUrl: string, origin: string) {
  const links = new Set<string>();
  const cleanedHtml = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, "");
  const anchors = /<a\b([^>]*)>/gi;
  const href = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i;

  for (const anchor of cleanedHtml.matchAll(anchors)) {
    const match = href.exec(anchor[1] ?? "");
    if (!match) continue;
    const candidate = resourcePath(
      (match[1] ?? match[2] ?? match[3] ?? "").replace(/&amp;/gi, "&"),
      pageUrl,
      origin,
    );
    if (!candidate || /(?:logout|signout|delete|remove|unsubscribe|reset-password|confirm)/i.test(candidate.pathname)) {
      continue;
    }
    if (
      !/\.(?:avif|css|gif|ico|jpe?g|js|json|mjs|pdf|png|svg|webp|woff2?|xml|zip)$/i
        .test(candidate.pathname)
    ) {
      candidate.search = "";
      links.add(candidate.href);
    }
  }

  const urls = [...links];
  return {
    urls: urls.slice(0, MAX_HTML_LINKS_PER_PAGE),
    omitted: urls.slice(MAX_HTML_LINKS_PER_PAGE),
  };
}

function scriptUrls(html: string, pageUrl: string, origin: string) {
  const scripts = new Set<string>();
  const externalScripts = new Set<string>();
  const scriptTags = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b([^>]*)>[\s\S]*?<\/script\s*>/gi, "<script $1>");
  const script = /<script\b([^>]*)>/gi;
  const src = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i;

  for (const tag of scriptTags.matchAll(script)) {
    const match = src.exec(tag[1] ?? "");
    if (!match) continue;
    const source = (match[1] ?? match[2] ?? match[3] ?? "").replace(/&amp;/gi, "&");
    const candidate = resourcePath(source, pageUrl, origin);
    if (candidate) {
      scripts.add(candidate.href);
      continue;
    }
    try {
      const external = new URL(source, pageUrl);
      if (
        ["http:", "https:"].includes(external.protocol) &&
        !external.username &&
        !external.password &&
        external.origin !== origin
      ) {
        external.hash = "";
        externalScripts.add(external.href);
      }
    } catch {
      continue;
    }
  }

  const urls = [...scripts];
  return {
    urls: urls.slice(0, MAX_SCRIPT_LINKS_PER_PAGE),
    omitted: urls.slice(MAX_SCRIPT_LINKS_PER_PAGE),
    externalUrls: [...externalScripts],
  };
}

function responseText(response: SafeFetchResult) {
  return Buffer.from(response.body).toString("utf8");
}

function contentType(response: SafeFetchResult) {
  const value = response.headers["content-type"];
  return (Array.isArray(value) ? value[0] : value ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
}

function isSuccessfulResponse(response: SafeFetchResult) {
  return Number.isInteger(response.statusCode) &&
    response.statusCode >= 200 &&
    response.statusCode < 300;
}

function validHttpStatus(response: SafeFetchResult) {
  return Number.isInteger(response.statusCode) &&
    response.statusCode >= 100 &&
    response.statusCode <= 599;
}

function isHtmlContentType(type: string) {
  return type === "text/html" || type === "application/xhtml+xml";
}

function isJavaScriptContentType(type: string) {
  return new Set([
    "application/javascript",
    "application/ecmascript",
    "text/javascript",
    "text/ecmascript",
    "application/x-javascript",
  ]).has(type);
}

function displayResource(url: string) {
  const parsed = new URL(url);
  return `${parsed.host}${parsed.pathname}`;
}

function safeScanError(error: unknown) {
  if (error instanceof Error && error.name === "SafeFetchTimeoutError") {
    return "The resource request timed out.";
  }
  return "The resource could not be fetched safely.";
}

export async function scanWebsiteSecrets(
  input: string,
  fetchSafeUrl: typeof safeFetchPublicUrl = fetchWebsiteResource,
) {
  let initial: SafeFetchResult;
  try {
    initial = await fetchSafeUrl(input);
  } catch (error) {
    throw new SecretScanError(
      error instanceof Error && error.name === "UnsafeUrlError"
        ? "The target URL is invalid or not publicly reachable."
        : safeScanError(error),
      error instanceof Error && error.name === "UnsafeUrlError" ? 400 : 502,
    );
  }

  if (!isSuccessfulResponse(initial)) {
    if (initial.redirectBlocked) {
      throw new SecretScanError(
        "The target website redirected outside the scanned origin; the destination was not requested.",
        502,
      );
    }
    const status = validHttpStatus(initial)
      ? ` HTTP ${initial.statusCode}`
      : "";
    throw new SecretScanError(
      `The target website returned an unsuccessful${status} response; its body was not scanned.`,
      502,
    );
  }
  if (!isHtmlContentType(contentType(initial))) {
    throw new SecretScanError(
      "The target website did not return a supported HTML content type; its body was not scanned.",
      502,
    );
  }

  const origin = new URL(initial.url).origin;
  const htmlQueue = [initial];
  const queuedHtml = new Set([initial.url]);
  const findings: WebsiteSecretFinding[] = [];
  const seenSecrets = new Set<string>();
  const checks: SecretCheck[] = [];
  const checkedResources = new Map<string, SecretCheck["status"]>();
  const scriptQueue: string[] = [];
  const omittedHtmlPages = new Map<string, string>();
  const omittedScripts = new Map<string, string>();
  const externalScripts = new Set<string>();
  let pagesScanned = 0;
  let pagesFailed = 0;

  function addCheck(
    key: string,
    check: SecretCheck,
  ) {
    const checkKey = `${check.kind}:${key}`;
    if (checkedResources.has(checkKey)) return;
    checkedResources.set(checkKey, check.status);
    checks.push(check);
  }

  function scanText(text: string, resource: string) {
    findings.push(
      ...detectSecrets(text, resource, seenSecrets).map(({ type, line, severity }) => ({
        type,
        resource,
        line,
        severity,
      })),
    );
  }

  while (htmlQueue.length > 0 && pagesScanned < MAX_HTML_PAGES) {
    const response = htmlQueue.shift();
    if (!response) continue;
    const pageUrl = resourcePath(response.url, response.url, origin);
    if (!pageUrl) {
      pagesFailed += 1;
      continue;
    }

    const shownPath = displayResource(pageUrl.href);
    const type = contentType(response);
    if (!isSuccessfulResponse(response)) {
      pagesFailed += 1;
      checks.push({
        resource: shownPath,
        kind: "HTML",
        status: "failed",
        ...(validHttpStatus(response) ? { httpStatus: response.statusCode } : {}),
        message: validHttpStatus(response)
          ? `The server returned HTTP ${response.statusCode}; the response body was not scanned.`
          : "The server returned an invalid HTTP status; the response body was not scanned.",
      });
      continue;
    }
    if (!isHtmlContentType(type)) {
      checks.push({
        resource: shownPath,
        kind: "HTML",
        status: "skipped",
        httpStatus: response.statusCode,
        message: "The response content type was not supported as HTML; its body was not scanned.",
      });
      continue;
    }

    const text = responseText(response);
    pagesScanned += 1;
    addCheck(pageUrl.href, {
      resource: shownPath,
      kind: "HTML",
      status: "scanned",
      httpStatus: response.statusCode,
    });
    scanText(text, shownPath);

    const discoveredScripts = scriptUrls(text, response.url, origin);
    for (const externalUrl of discoveredScripts.externalUrls) {
      externalScripts.add(externalUrl);
    }
    for (const omittedScript of discoveredScripts.omitted) {
      if (
        !checkedResources.has(`JavaScript:${omittedScript}`) &&
        !scriptQueue.includes(omittedScript)
      ) {
        omittedScripts.set(
          omittedScript,
          "The per-page JavaScript discovery limit was reached; this resource was not requested.",
        );
      }
    }
    for (const scriptUrl of discoveredScripts.urls) {
      omittedScripts.delete(scriptUrl);
      if (!checkedResources.has(`JavaScript:${scriptUrl}`) && !scriptQueue.includes(scriptUrl)) {
        scriptQueue.push(scriptUrl);
      }
    }

    const discoveredHtml = htmlLinks(text, response.url, origin);
    for (const link of discoveredHtml.omitted) {
      if (
        !queuedHtml.has(link) &&
        !/\.{1,2}(?:\/|$)/.test(new URL(link).pathname)
      ) {
        omittedHtmlPages.set(
          link,
          "The per-page HTML link discovery limit was reached; this page was not requested.",
        );
      }
    }
    for (const link of discoveredHtml.urls) {
      omittedHtmlPages.delete(link);
      if (
        !queuedHtml.has(link) &&
        !/\.{1,2}(?:\/|$)/.test(new URL(link).pathname)
      ) {
        if (queuedHtml.size >= MAX_HTML_PAGES) {
          omittedHtmlPages.set(
            link,
            "The overall HTML page limit was reached; this page was not requested.",
          );
          continue;
        }
        queuedHtml.add(link);
        try {
          const next = await fetchSafeUrl(link);
          if (next.redirectBlocked || new URL(next.url).origin !== origin) {
            pagesFailed += 1;
            addCheck(link, {
              resource: displayResource(link),
              kind: "HTML",
              status: "failed",
              message: "The request redirected outside the scanned origin; the destination was not requested.",
            });
          } else {
            htmlQueue.push(next);
          }
        } catch (error) {
          pagesFailed += 1;
          addCheck(link, {
            resource: displayResource(link),
            kind: "HTML",
            status: "failed",
            message: safeScanError(error),
          });
        }
      }
    }
  }

  for (const [omittedUrl, message] of omittedHtmlPages) {
    addCheck(omittedUrl, {
      resource: displayResource(omittedUrl),
      kind: "HTML",
      status: "omitted",
      message,
    });
  }

  const limitedScripts = scriptQueue.slice(0, MAX_SCRIPT_FILES);
  for (const scriptUrl of limitedScripts) {
    omittedScripts.delete(scriptUrl);
  }
  for (const omittedScript of scriptQueue.slice(MAX_SCRIPT_FILES)) {
    omittedScripts.set(
      omittedScript,
      "The overall JavaScript resource limit was reached; this resource was not requested.",
    );
  }
  for (const [omittedScript, message] of omittedScripts) {
    addCheck(omittedScript, {
      resource: displayResource(omittedScript),
      kind: "JavaScript",
      status: "omitted",
      message,
    });
  }
  for (const scriptUrl of limitedScripts) {
    if (checkedResources.has(scriptUrl)) continue;
    const shownPath = displayResource(scriptUrl);
    try {
      const response = await fetchSafeUrl(scriptUrl);
      if (response.redirectBlocked || new URL(response.url).origin !== origin) {
        addCheck(scriptUrl, {
          resource: shownPath,
          kind: "JavaScript",
          status: "failed",
          message: "The request redirected outside the scanned origin; the destination was not requested.",
        });
        continue;
      }

      if (!isSuccessfulResponse(response)) {
        addCheck(scriptUrl, {
          resource: shownPath,
          kind: "JavaScript",
          status: "failed",
          ...(validHttpStatus(response) ? { httpStatus: response.statusCode } : {}),
          message: validHttpStatus(response)
            ? `The server returned HTTP ${response.statusCode}; the response body was not scanned.`
            : "The server returned an invalid HTTP status; the response body was not scanned.",
        });
        continue;
      }

      const responseKind = contentType(response);
      if (!isJavaScriptContentType(responseKind)) {
        addCheck(scriptUrl, {
          resource: shownPath,
          kind: "JavaScript",
          status: "skipped",
          httpStatus: response.statusCode,
          message: "The response content type was not supported as JavaScript; its body was not scanned.",
        });
        continue;
      }

      addCheck(scriptUrl, {
        resource: shownPath,
        kind: "JavaScript",
        status: "scanned",
        httpStatus: response.statusCode,
      });
      scanText(responseText(response), shownPath);
    } catch (error) {
      addCheck(scriptUrl, {
        resource: shownPath,
        kind: "JavaScript",
        status: "failed",
        message: safeScanError(error),
      });
    }
  }

  if (externalScripts.size > 0) {
    checks.push({
      resource: "External JavaScript resources",
      kind: "JavaScript",
      status: "external",
      count: externalScripts.size,
      message: "External scripts are outside the same-origin scan scope and were not requested.",
    });
  }
  const countStatus = (status: SecretCheck["status"]) =>
    checks.reduce(
      (total, check) =>
        total + (check.status === status ? check.count ?? 1 : 0),
      0,
    );
  const resourcesScanned = countStatus("scanned");
  const resourcesFailed = countStatus("failed");
  const resourcesSkipped = countStatus("skipped");
  const resourcesOmitted = countStatus("omitted");
  return {
    target: new URL(initial.url).origin,
    pagesScanned,
    pagesFailed,
    resourcesScanned,
    resourcesFailed,
    resourcesSkipped,
    resourcesOmitted,
    resourcesExternal: externalScripts.size,
    checks,
    complete: resourcesFailed === 0 && resourcesSkipped === 0 &&
      resourcesOmitted === 0 &&
      htmlQueue.length === 0 && scriptQueue.length <= MAX_SCRIPT_FILES,
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter(({ severity }) => severity === "critical").length,
      high: findings.filter(({ severity }) => severity === "high").length,
      medium: findings.filter(({ severity }) => severity === "medium").length,
    },
  };
}
