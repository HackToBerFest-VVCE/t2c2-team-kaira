import {
  ResponseTooLargeError,
  SafeFetchTimeoutError,
  safeFetchPublicUrl,
  UnsafeUrlError,
} from "./url-safety.ts";
import { auditWebsiteResponse } from "./website-checks.ts";

const MAX_REQUEST_BYTES = 4_096;
const MAX_URL_LENGTH = 2_048;

class InvalidAuditRequestError extends Error {}
class AuditRequestTooLargeError extends Error {}

function errorResponse(status: number, code: string, message: string): Response {
  return Response.json({ error: { code, message } }, { status });
}

function reportUrl(input: string): URL {
  const url = new URL(input);
  url.search = "";
  url.hash = "";
  return url;
}

async function readRequestJson(request: Request): Promise<unknown> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > MAX_REQUEST_BYTES) {
    throw new AuditRequestTooLargeError();
  }

  if (!request.body) throw new InvalidAuditRequestError();

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

  const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new InvalidAuditRequestError();
  }
}

function auditUrlFromPayload(payload: unknown): string {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new InvalidAuditRequestError();
  }

  const url = (payload as Record<string, unknown>).url;
  if (typeof url !== "string") throw new InvalidAuditRequestError();

  const trimmedUrl = url.trim();
  if (!trimmedUrl || trimmedUrl.length > MAX_URL_LENGTH) {
    throw new InvalidAuditRequestError();
  }
  return trimmedUrl;
}

export function createAuditPostHandler(fetchSafeUrl: typeof safeFetchPublicUrl = safeFetchPublicUrl) {
  return async function POST(request: Request): Promise<Response> {
    const contentType = request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json" && !contentType?.endsWith("+json")) {
      return errorResponse(415, "UNSUPPORTED_MEDIA_TYPE", "Send the audit request as JSON.");
    }

    let url: string;
    try {
      url = auditUrlFromPayload(await readRequestJson(request));
    } catch (error) {
      if (error instanceof AuditRequestTooLargeError) {
        return errorResponse(413, "REQUEST_TOO_LARGE", "The audit request is too large.");
      }
      return errorResponse(400, "INVALID_REQUEST", "Provide a JSON object with a valid URL string.");
    }

    try {
      const result = await fetchSafeUrl(url);
      const requestedUrl = new URL(url);
      const finalUrl = new URL(result.url);
      const queryChanged = requestedUrl.search !== finalUrl.search;
      requestedUrl.hash = "";
      finalUrl.hash = "";
      const redirected = requestedUrl.href !== finalUrl.href;
      const findings = auditWebsiteResponse({
        requestedUrl: url,
        finalUrl: result.url,
        statusCode: result.statusCode,
        headers: result.headers,
      });

      return Response.json({
        target: new URL(url).origin,
        finalTarget: new URL(result.url).origin,
        requestedUrl: reportUrl(url).href,
        finalUrl: reportUrl(result.url).href,
        redirected,
        queryChanged,
        statusCode: result.statusCode,
        scannedAt: new Date().toISOString(),
        findings,
      });
    } catch (error) {
      if (error instanceof UnsafeUrlError) {
        return errorResponse(400, "UNSAFE_TARGET", "The target URL is invalid or not publicly reachable.");
      }
      if (error instanceof SafeFetchTimeoutError) {
        return errorResponse(504, "TARGET_TIMEOUT", "The target did not respond within the time limit.");
      }
      if (error instanceof ResponseTooLargeError) {
        return errorResponse(502, "TARGET_RESPONSE_TOO_LARGE", "The target response exceeded the safety limit.");
      }
      return errorResponse(502, "TARGET_UNAVAILABLE", "The target could not be fetched safely.");
    }
  };
}