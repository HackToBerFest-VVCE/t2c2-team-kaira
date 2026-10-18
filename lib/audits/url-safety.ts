import { lookup as dnsLookup } from "node:dns/promises";
import type { IncomingHttpHeaders, RequestOptions } from "node:http";
import { request as httpRequest } from "node:http";
import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface SafeTransportResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: AsyncIterable<Uint8Array>;
  cancel(): void;
}

export type HostResolver = (hostname: string) => Promise<ResolvedAddress[]>;
export type PinnedTransport = (
  url: URL,
  address: ResolvedAddress,
  signal: AbortSignal,
) => Promise<SafeTransportResponse>;

export interface SafeFetchOptions {
  resolveHost?: HostResolver;
  transport?: PinnedTransport;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRedirects?: number;
}

export interface SafeFetchResult {
  url: string;
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

export interface NodeRequestAdapters {
  http: typeof httpRequest;
  https: typeof httpsRequest;
}

const IPV4_BLOCKED_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

const IPV6_BLOCKED_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["2620:4f:8000::", 48],
  ["3fff::", 20],
];

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeUrlError";
  }
}

export class SafeFetchTimeoutError extends Error {
  constructor() {
    super("The request exceeded its time limit.");
    this.name = "SafeFetchTimeoutError";
  }
}

export class ResponseTooLargeError extends Error {
  constructor() {
    super("The response exceeded the configured size limit.");
    this.name = "ResponseTooLargeError";
  }
}

function ipv4ToBigInt(address: string): bigint {
  return address
    .split(".")
    .reduce((result, part) => (result << BigInt(8)) | BigInt(part), BigInt(0));
}

function ipv6ToBigInt(address: string): bigint | null {
  let normalized = address.toLowerCase();

  if (normalized.includes(".")) {
    const lastColon = normalized.lastIndexOf(":");
    const ipv4Tail = normalized.slice(lastColon + 1);
    if (isIP(ipv4Tail) !== 4) return null;
    const ipv4Number = ipv4ToBigInt(ipv4Tail);
    const firstGroup = Number((ipv4Number >> BigInt(16)) & BigInt(0xffff)).toString(16);
    const secondGroup = Number(ipv4Number & BigInt(0xffff)).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${firstGroup}:${secondGroup}`;
  }

  const compressionIndex = normalized.indexOf("::");
  if (compressionIndex !== normalized.lastIndexOf("::")) return null;

  const left = compressionIndex === -1 ? normalized : normalized.slice(0, compressionIndex);
  const right = compressionIndex === -1 ? "" : normalized.slice(compressionIndex + 2);
  const leftGroups = left ? left.split(":") : [];
  const rightGroups = right ? right.split(":") : [];
  const missingGroups = 8 - leftGroups.length - rightGroups.length;

  if ((compressionIndex === -1 && missingGroups !== 0) || missingGroups < 0) return null;

  const groups = [
    ...leftGroups,
    ...Array.from({ length: missingGroups }, () => "0"),
    ...rightGroups,
  ];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }

  return groups.reduce(
    (result, group) => (result << BigInt(16)) | BigInt(`0x${group}`),
    BigInt(0),
  );
}

function inCidr(address: bigint, network: bigint, prefixLength: number, bitLength: number): boolean {
  const shift = BigInt(bitLength - prefixLength);
  return address >> shift === network >> shift;
}

function isPublicIpv4(address: string): boolean {
  const numericAddress = ipv4ToBigInt(address);
  return !IPV4_BLOCKED_CIDRS.some(([network, prefixLength]) =>
    inCidr(numericAddress, ipv4ToBigInt(network), prefixLength, 32),
  );
}

function isPublicIpv6(address: string): boolean {
  const numericAddress = ipv6ToBigInt(address);
  if (numericAddress === null) return false;

  const ipv4MappedPrefix = BigInt("0xffff");
  if (numericAddress >> BigInt(32) === ipv4MappedPrefix) {
    const mappedIpv4 = Number(numericAddress & BigInt("0xffffffff"))
      .toString(16)
      .padStart(8, "0");
    const mappedAddress = [0, 2, 4, 6]
      .map((offset) => Number.parseInt(mappedIpv4.slice(offset, offset + 2), 16))
      .join(".");
    return isPublicIpv4(mappedAddress);
  }

  const globalUnicastPrefix = BigInt(0x2000) << BigInt(112);
  const globalUnicastPrefixLength = 3;
  if (!inCidr(numericAddress, globalUnicastPrefix, globalUnicastPrefixLength, 128)) {
    return false;
  }

  return !IPV6_BLOCKED_CIDRS.some(([network, prefixLength]) =>
    inCidr(numericAddress, ipv6ToBigInt(network) ?? BigInt(0), prefixLength, 128),
  );
}

export function isPublicAddress(address: string, family: number = isIP(address)): boolean {
  if (family === 4 && isIP(address) === 4) return isPublicIpv4(address);
  if (family === 6 && isIP(address) === 6) return isPublicIpv6(address);
  return false;
}

function hostnameForLookup(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function parseHttpUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UnsafeUrlError("The URL is invalid.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UnsafeUrlError("Only HTTP and HTTPS URLs are allowed.");
  }
  if (url.username || url.password) {
    throw new UnsafeUrlError("URLs containing credentials are not allowed.");
  }
  if (url.port) {
    throw new UnsafeUrlError("Only the standard HTTP and HTTPS ports are allowed.");
  }

  const hostname = hostnameForLookup(url.hostname).toLowerCase().replace(/\.$/, "");
  if (
    !hostname ||
    ["localhost", "local", "internal", "test", "invalid", "example"].some(
      (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`),
    )
  ) {
    throw new UnsafeUrlError("Local and reserved hostnames are not allowed.");
  }

  return url;
}

async function resolveHostAddresses(hostname: string): Promise<ResolvedAddress[]> {
  const records = await dnsLookup(hostname, { all: true, verbatim: true });
  return records.map(({ address, family }) => ({
    address,
    family: family as 4 | 6,
  }));
}

export async function validatePublicUrl(
  input: string,
  resolveHost: HostResolver = resolveHostAddresses,
): Promise<{ url: URL; addresses: ResolvedAddress[] }> {
  const url = parseHttpUrl(input);
  const hostname = hostnameForLookup(url.hostname);
  const literalFamily = isIP(hostname);
  const addresses = literalFamily
    ? [{ address: hostname, family: literalFamily as 4 | 6 }]
    : await resolveHost(hostname);

  if (addresses.length === 0) {
    throw new UnsafeUrlError("The hostname did not resolve to an address.");
  }
  if (addresses.some(({ address, family }) => !isPublicAddress(address, family))) {
    throw new UnsafeUrlError("The hostname resolves to a non-public address.");
  }

  return { url, addresses };
}

export function createPinnedLookup(address: ResolvedAddress): NonNullable<RequestOptions["lookup"]> {
  if (!isPublicAddress(address.address, address.family)) {
    throw new UnsafeUrlError("A pinned lookup requires a public IP address.");
  }

  return ((_hostname: string, options: { all?: boolean }, callback: (...args: unknown[]) => void) => {
    if (options?.all) {
      callback(null, [{ address: address.address, family: address.family }]);
      return;
    }
    callback(null, address.address, address.family);
  }) as NonNullable<RequestOptions["lookup"]>;
}

export function createNodePinnedTransport(
  adapters: NodeRequestAdapters = { http: httpRequest, https: httpsRequest },
): PinnedTransport {
  return (url, address, signal) =>
    new Promise((resolve, reject) => {
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }

      const hostname = hostnameForLookup(url.hostname);
      const request = (url.protocol === "https:" ? adapters.https : adapters.http)(
        {
          protocol: url.protocol,
          hostname,
          port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80,
          path: `${url.pathname}${url.search}`,
          method: "GET",
          agent: false,
          headers: {
            host: url.host,
            "accept-encoding": "identity",
          },
          lookup: createPinnedLookup(address),
          ...(url.protocol === "https:" && isIP(hostname) === 0 ? { servername: hostname } : {}),
        },
        (response) => {
          const abortResponse = () => {
            response.destroy(
              signal.reason instanceof Error ? signal.reason : new Error("Request aborted."),
            );
          };
          const removeAbortListener = () => signal.removeEventListener("abort", abortResponse);
          if (signal.aborted) abortResponse();
          else signal.addEventListener("abort", abortResponse, { once: true });
          response.once("close", removeAbortListener);

          resolve({
            statusCode: response.statusCode ?? 0,
            headers: response.headers,
            body: response,
            cancel: () => response.destroy(),
          });
        },
      );

      const abortRequest = () => {
        request.destroy(
          signal.reason instanceof Error ? signal.reason : new Error("Request aborted."),
        );
      };
      signal.addEventListener("abort", abortRequest, { once: true });
      request.once("close", () => signal.removeEventListener("abort", abortRequest));
      request.once("error", (error) => reject(error));
      request.end();
    });
}

const nodePinnedTransport = createNodePinnedTransport();

function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);

  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

async function readLimitedBody(
  response: SafeTransportResponse,
  maxResponseBytes: number,
  signal: AbortSignal,
): Promise<Buffer> {
  const contentLength = Number(response.headers["content-length"]);
  if (Number.isFinite(contentLength) && contentLength > maxResponseBytes) {
    response.cancel();
    throw new ResponseTooLargeError();
  }

  const iterator = response.body[Symbol.asyncIterator]();
  const chunks: Buffer[] = [];
  let bytesRead = 0;

  try {
    while (true) {
      const item = await raceAbort(iterator.next(), signal);
      if (item.done) break;

      const chunk = Buffer.from(item.value);
      bytesRead += chunk.length;
      if (bytesRead > maxResponseBytes) throw new ResponseTooLargeError();
      chunks.push(chunk);
    }
  } catch (error) {
    response.cancel();
    if (error instanceof ResponseTooLargeError) throw error;
    if (signal.aborted) throw signal.reason;
    throw error;
  }

  return Buffer.concat(chunks, bytesRead);
}

function redirectUrl(response: SafeTransportResponse, currentUrl: URL): URL | null {
  if (![301, 302, 303, 307, 308].includes(response.statusCode)) return null;
  const location = response.headers.location;
  if (typeof location !== "string" || location.length === 0) {
    response.cancel();
    throw new UnsafeUrlError("The redirect did not include a valid location.");
  }

  try {
    return new URL(location, currentUrl);
  } catch {
    response.cancel();
    throw new UnsafeUrlError("The redirect location is invalid.");
  }
}

export function createSafeFetcher(options: SafeFetchOptions = {}) {
  const resolveHost = options.resolveHost ?? resolveHostAddresses;
  const transport = options.transport ?? nodePinnedTransport;
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maxResponseBytes = options.maxResponseBytes ?? 1_048_576;
  const maxRedirects = options.maxRedirects ?? 3;

  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive integer.");
  }
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw new RangeError("maxResponseBytes must be a positive integer.");
  }
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0) {
    throw new RangeError("maxRedirects must be a non-negative integer.");
  }

  return async function safeFetch(input: string): Promise<SafeFetchResult> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort(new SafeFetchTimeoutError());
    }, timeoutMs);

    try {
      let validated = await raceAbort(validatePublicUrl(input, resolveHost), controller.signal);
      let redirectsFollowed = 0;
      const visited = new Set<string>();

      while (true) {
        const requestKey = new URL(validated.url);
        requestKey.hash = "";
        if (visited.has(requestKey.href)) throw new UnsafeUrlError("A redirect loop was detected.");
        visited.add(requestKey.href);

        const response = await raceAbort(
          transport(validated.url, validated.addresses[0], controller.signal),
          controller.signal,
        );
        const nextUrl = redirectUrl(response, validated.url);

        if (nextUrl) {
          response.cancel();
          if (redirectsFollowed >= maxRedirects) {
            throw new UnsafeUrlError("The redirect limit was exceeded.");
          }
          redirectsFollowed += 1;
          validated = await raceAbort(validatePublicUrl(nextUrl.href, resolveHost), controller.signal);
          continue;
        }

        const body = await readLimitedBody(response, maxResponseBytes, controller.signal);
        return {
          url: validated.url.href,
          statusCode: response.statusCode,
          headers: response.headers,
          body,
        };
      }
    } catch (error) {
      if (timedOut) throw new SafeFetchTimeoutError();
      throw error;
    } finally {
      clearTimeout(timer);
    }
  };
}

export const safeFetchPublicUrl = createSafeFetcher();