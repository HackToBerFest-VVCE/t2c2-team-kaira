import type { SafeFetchResult } from "./url-safety.ts";
import { auditWebsiteResponse, type AuditFinding } from "./website-checks.ts";

const MAX_PAGES = 5;
const MAX_LINKS_PER_PAGE = 50;
const AVOID_GET_ACTION_PATH = /(?:logout|signout|delete|remove|unsubscribe|reset-password|confirm)/i;

type SafeFetcher = (url: string) => Promise<SafeFetchResult>;

function canonicalPageUrl(input: string, base: string, origin: string) {
  let url: URL;
  try {
    url = new URL(input, base);
  } catch {
    return null;
  }

  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.origin !== origin ||
    url.username ||
    url.password ||
    AVOID_GET_ACTION_PATH.test(url.pathname)
  ) {
    return null;
  }

  url.search = "";
  url.hash = "";
  return url.href;
}

function extractPageLinks(body: Uint8Array, baseUrl: string, origin: string) {
  const html = Buffer.from(body)
    .toString("utf8")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, "")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, "");
  const links = new Set<string>();
  const anchorPattern = /<a\b([^>]*)>/gi;
  const hrefPattern = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i;

  for (const anchor of html.matchAll(anchorPattern)) {
    const match = hrefPattern.exec(anchor[1] ?? "");
    if (!match) continue;
    const href = (match[1] ?? match[2] ?? match[3] ?? "").replace(/&amp;/gi, "&");
    const pageUrl = canonicalPageUrl(href, baseUrl, origin);
    if (
      pageUrl &&
      !/\.(?:avif|css|gif|ico|jpe?g|js|json|mjs|pdf|png|svg|webp|woff2?|xml|zip)$/i
        .test(new URL(pageUrl).pathname)
    ) {
      links.add(pageUrl);
    }
    if (links.size >= MAX_LINKS_PER_PAGE) break;
  }

  return [...links];
}

function isHtmlResponse(response: SafeFetchResult) {
  const contentType = response.headers["content-type"];
  if (typeof contentType === "string" && /text\/html|application\/xhtml\+xml/i.test(contentType)) {
    return true;
  }

  return /^\s*(?:<!doctype\s+html|<html\b)/i.test(
    Buffer.from(response.body).toString("utf8", 0, 256),
  );
}

export async function scanSameOriginPages(
  requestedUrl: string,
  initialResponse: SafeFetchResult,
  fetchSafeUrl: SafeFetcher,
) {
  const origin = new URL(initialResponse.url).origin;
  const queue = [initialResponse];
  const queuedUrls = new Set<string>();
  const pages = new Set<string>();
  const findings: Array<AuditFinding & { pageUrl: string }> = [];
  let failedPages = 0;
  let requestsStarted = 1;
  const omittedUrls = new Set<string>();

  while (queue.length > 0 && pages.size < MAX_PAGES) {
    const response = queue.shift();
    if (!response) continue;

    const finalUrl = new URL(response.url);
    finalUrl.search = "";
    finalUrl.hash = "";
    const pageUrl = finalUrl.href;
    if (pages.has(pageUrl)) continue;
    pages.add(pageUrl);

    const pageFindings = auditWebsiteResponse({
      requestedUrl: pages.size === 1 ? requestedUrl : pageUrl,
      finalUrl: response.url,
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body,
    });
    findings.push(...pageFindings.map((finding) => ({
      ...finding,
      pageUrl,
    })));

    if (!isHtmlResponse(response) || new URL(response.url).origin !== origin) {
      continue;
    }

    for (const discoveredUrl of extractPageLinks(response.body, response.url, origin)) {
      if (
        queuedUrls.has(discoveredUrl) ||
        pages.has(discoveredUrl) ||
        omittedUrls.has(discoveredUrl)
      ) continue;
      if (requestsStarted >= MAX_PAGES) {
        omittedUrls.add(discoveredUrl);
        continue;
      }
      queuedUrls.add(discoveredUrl);
      requestsStarted += 1;

      try {
        const nextResponse = await fetchSafeUrl(discoveredUrl);
        if (new URL(nextResponse.url).origin !== origin) {
          failedPages += 1;
          continue;
        }
        queue.push(nextResponse);
      } catch {
        failedPages += 1;
      }
    }
  }

  return {
    pagesScanned: pages.size,
    pagesFailed: failedPages,
    pagesOmitted: omittedUrls.size,
    findings,
  };
}
