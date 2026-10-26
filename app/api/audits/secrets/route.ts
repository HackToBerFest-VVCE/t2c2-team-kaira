import { NextResponse } from "next/server";
import { SecretScanError } from "../../../../lib/audits/secret-scanner.ts";
import { scanWebsiteSecrets } from "../../../../lib/audits/website-secret-scan.ts";
import { UnsafeUrlError } from "../../../../lib/audits/url-safety.ts";

const maximumRequestBytes = 4_096;
const maximumUrlLength = 2_048;

export async function POST(request: Request) {
  try {
    const contentType = request.headers
      .get("content-type")
      ?.split(";", 1)[0]
      .trim()
      .toLowerCase();
    if (contentType !== "application/json" && !contentType?.endsWith("+json")) {
      return NextResponse.json(
        { error: "Send the secret scan request as JSON." },
        { status: 415 },
      );
    }

    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > maximumRequestBytes) {
      return NextResponse.json(
        { error: "The scan request is too large." },
        { status: 413 },
      );
    }

    const bodyText = await request.text();
    if (Buffer.byteLength(bodyText, "utf8") > maximumRequestBytes) {
      return NextResponse.json(
        { error: "The scan request is too large." },
        { status: 413 },
      );
    }

    let body: unknown;
    try {
      body = JSON.parse(bodyText);
    } catch {
      return NextResponse.json(
        { error: "The request body must contain valid JSON." },
        { status: 400 },
      );
    }

    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return NextResponse.json(
        { error: "The request body must be a JSON object." },
        { status: 400 },
      );
    }

    const url = (body as { url?: unknown }).url;
    if (typeof url !== "string" || !url.trim() || url.trim().length > maximumUrlLength) {
      return NextResponse.json(
        { error: "Provide a valid website URL to scan." },
        { status: 400 },
      );
    }

    const result = await scanWebsiteSecrets(url.trim());
    return NextResponse.json({
      scannedAt: new Date().toISOString(),
      ...result,
    });
  } catch (error) {
    if (error instanceof SecretScanError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.status },
      );
    }

    if (error instanceof UnsafeUrlError) {
      return NextResponse.json(
        { error: "The target URL is invalid or not publicly reachable." },
        { status: 400 },
      );
    }

    return NextResponse.json(
      { error: "The website secret scan could not be completed." },
      { status: 502 },
    );
  }
}
