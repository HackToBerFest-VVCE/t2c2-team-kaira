
import {
  ResponseTooLargeError,
  SafeFetchTimeoutError,
  safeFetchPublicUrl,
  UnsafeUrlError,
} from "./url-safety.ts";
import { scanSameOriginPages } from "./website-crawl.ts";

const MAX_REQUEST_BYTES = 4_096;
const MAX_URL_LENGTH = 2_048;
const DEFAULT_RATE_LIMIT = 10;
const DEFAULT_WINDOW_MS = 60_000;

class InvalidAuditRequestError extends Error {}
class AuditRequestTooLargeError extends Error {}

type RateLimitDecision = {
  allowed: boolean;
  retryAfterSeconds: number;
  remaining: number;
};

type RateLimiter = (key: string) => RateLimitDecision;

type RateLimiterOptions = {
  limit?: number;
  windowMs?: number;
  now?: () => number;
};

export function createInMemoryRateLimiter({
  limit = DEFAULT_RATE_LIMIT,
  windowMs = DEFAULT_WINDOW_MS,
  now = Date.now,
}: RateLimiterOptions = {}): RateLimiter {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error("Rate limit must be a positive integer.");
  }

  if (!Number.isFinite(windowMs) || windowMs < 1) {
    throw new Error("Rate-limit window must be positive.");
  }

  const buckets = new Map<string, { count: number; resetAt: number }>();
  let callsSinceCleanup = 0;

  return (key: string): RateLimitDecision => {
    const currentTime = now();

    callsSinceCleanup += 1;

    if (callsSinceCleanup >= 100) {
      for (const [storedKey, bucket] of buckets) {
        if (currentTime >= bucket.resetAt) {
          buckets.delete(storedKey);
        }
      }

      callsSinceCleanup = 0;
    }

    let bucket = buckets.get(key);

    if (!bucket || currentTime >= bucket.resetAt) {
      bucket = {
        count: 0,
        resetAt: currentTime + windowMs,
      };

      buckets.set(key, bucket);
    }

    if (bucket.count >= limit) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(
          1,
          Math.ceil((bucket.resetAt - currentTime) / 1000),
        ),
        remaining: 0,
      };
    }

    bucket.count += 1;

    return {
      allowed: true,
      retryAfterSeconds: 0,
      remaining: limit - bucket.count,
    };
  };
}

const defaultRateLimiter = createInMemoryRateLimiter();

function errorResponse(
  status: number,
  code: string,
  message: string,
  headers?: HeadersInit,
): Response {
  return Response.json(
    { error: { code, message } },
    { status, headers },
  );
}

function reportUrl(input: string): URL {
  const url = new URL(input);
  url.search = "";
  url.hash = "";
  return url;
}

function clientRateLimitKey(request: Request): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  const forwardedIp = forwardedFor?.split(",")[0]?.trim();
  const realIp = request.headers.get("x-real-ip")?.trim();
  const candidate = forwardedIp || realIp;

  if (!candidate || candidate.length > 64) {
    return "unknown";
  }

  return candidate;
}

async function readRequestJson(request: Request): Promise<unknown> {
  const contentLength = request.headers.get("content-length");

  if (contentLength && Number(contentLength) > MAX_REQUEST_BYTES) {
    throw new AuditRequestTooLargeError();
  }

  if (!request.body) {
    throw new InvalidAuditRequestError();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytesRead = 0;

  while (true) {
    const { done, value } = await reader.read();

    if (done) break;

    bytesRead += value.byteLength;

    if (bytesRead > MAX_REQUEST_BYTES) {
      await reader.cancel();
      throw new AuditRequestTooLargeError();
    }

    chunks.push(value);
  }

  const body = Buffer.concat(
    chunks.map((chunk) => Buffer.from(chunk)),
  ).toString("utf8");

  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new InvalidAuditRequestError();
  }
}

function auditUrlFromPayload(payload: unknown): string {
  if (
    typeof payload !== "object" ||
    payload === null ||
    Array.isArray(payload)
  ) {
    throw new InvalidAuditRequestError();
  }

  const url = (payload as Record<string, unknown>).url;

  if (typeof url !== "string") {
    throw new InvalidAuditRequestError();
  }

  const trimmedUrl = url.trim();

  if (!trimmedUrl || trimmedUrl.length > MAX_URL_LENGTH) {
    throw new InvalidAuditRequestError();
  }

  return trimmedUrl;
}

export function createAuditPostHandler(
  fetchSafeUrl: typeof safeFetchPublicUrl = safeFetchPublicUrl,
  rateLimiter: RateLimiter = defaultRateLimiter,
) {
  return async function POST(request: Request): Promise<Response> {
    const rateLimit = rateLimiter(clientRateLimitKey(request));

    if (!rateLimit.allowed) {
      return errorResponse(
        429,
        "RATE_LIMIT_EXCEEDED",
        "Too many audit requests. Please wait before trying again.",
        {
          "Retry-After": String(rateLimit.retryAfterSeconds),
        },
      );
    }

    const contentType = request.headers
      .get("content-type")
      ?.split(";", 1)[0]
      .trim()
      .toLowerCase();

    if (
      contentType !== "application/json" &&
      !contentType?.endsWith("+json")
    ) {
      return errorResponse(
        415,
        "UNSUPPORTED_MEDIA_TYPE",
        "Send the audit request as JSON.",
      );
    }

    let url: string;

    try {
      url = auditUrlFromPayload(await readRequestJson(request));
    } catch (error) {
      if (error instanceof AuditRequestTooLargeError) {
        return errorResponse(
          413,
          "REQUEST_TOO_LARGE",
          "The audit request is too large.",
        );
      }

      return errorResponse(
        400,
        "INVALID_REQUEST",
        "Provide a JSON object with a valid URL string.",
      );
    }

    try {
      const result = await fetchSafeUrl(url);
      const requestedUrl = new URL(url);
      const finalUrl = new URL(result.url);
      const queryChanged = requestedUrl.search !== finalUrl.search;

      requestedUrl.hash = "";
      finalUrl.hash = "";

      const redirected = requestedUrl.href !== finalUrl.href;

      const scan = await scanSameOriginPages(url, result, fetchSafeUrl);

      return Response.json({
        target: new URL(url).origin,
        finalTarget: new URL(result.url).origin,
        requestedUrl: reportUrl(url).href,
        finalUrl: reportUrl(result.url).href,
        redirected,
        queryChanged,
        statusCode: result.statusCode,
        scanMode: "passive_http_same_origin",
        pageLimit: 5,
        pagesScanned: scan.pagesScanned,
        pagesFailed: scan.pagesFailed,
        pagesOmitted: scan.pagesOmitted,
        scannedAt: new Date().toISOString(),
        findings: scan.findings,
      });
    } catch (error) {
      if (error instanceof UnsafeUrlError) {
        return errorResponse(
          400,
          "UNSAFE_TARGET",
          "The target URL is invalid or not publicly reachable.",
        );
      }

      if (error instanceof SafeFetchTimeoutError) {
        return errorResponse(
          504,
          "TARGET_TIMEOUT",
          "The target did not respond within the time limit.",
        );
      }

      if (error instanceof ResponseTooLargeError) {
        return errorResponse(
          502,
          "TARGET_RESPONSE_TOO_LARGE",
          "The target response exceeded the safety limit.",
        );
      }

      return errorResponse(
        502,
        "TARGET_UNAVAILABLE",
        "The target could not be fetched safely.",
      );
    }
  };
}
