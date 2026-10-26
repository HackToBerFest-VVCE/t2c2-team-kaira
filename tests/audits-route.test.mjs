import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "../app/api/audits/route.ts";
import { createAuditPostHandler } from "../lib/audits/audit-handler.ts";
import {
  createSafeFetcher,
  ResponseTooLargeError,
  SafeFetchTimeoutError,
  UnsafeUrlError,
} from "../lib/audits/url-safety.ts";

function request(body, options = {}) {
  return new Request("http://kaira.test/api/audits", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...options.headers,
    },
    body,
  });
}

const safeResult = {
  url: "https://shop.example.testdomain.com/final",
  statusCode: 200,
  headers: {
    "content-security-policy": "default-src 'self'; script-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "SAMEORIGIN",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
    "set-cookie": ["session=secret; Secure; HttpOnly; SameSite=Lax"],
  },
  body: Buffer.from("<html></html>"),
};

function transportResponse(statusCode, headers = {}) {
  return {
    statusCode,
    headers,
    body: (async function* () {
      yield Buffer.from("<html>mocked</html>");
    })(),
    cancel() {},
  };
}

test("exports a Next.js POST handler using its default Node.js runtime", () => {
  assert.equal(typeof POST, "function");
});

test("POST validates the payload, calls safe fetch once, and returns structured findings", async () => {
  const calls = [];
  const post = createAuditPostHandler(async (url) => {
    calls.push(url);
    return safeResult;
  });

  const response = await post(request(JSON.stringify({ url: "  https://shop.example.testdomain.com/start  " })));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(calls, ["https://shop.example.testdomain.com/start"]);
  assert.equal(body.target, "https://shop.example.testdomain.com");
  assert.equal(body.finalTarget, "https://shop.example.testdomain.com");
  assert.equal(body.requestedUrl, "https://shop.example.testdomain.com/start");
  assert.equal(body.finalUrl, "https://shop.example.testdomain.com/final");
  assert.equal(body.redirected, true);
  assert.equal(body.queryChanged, false);
  assert.equal(body.statusCode, 200);
  assert.equal(typeof body.scannedAt, "string");
  assert.equal(body.findings.find(({ id }) => id === "transport.https").status, "pass");
  assert.ok(body.findings.every(({ id, severity, title, explanation, evidence, recommendation }) =>
    id && severity && title && explanation && evidence && recommendation));
  assert.doesNotMatch(JSON.stringify(body), /session=secret/);
});

test("rejects unsupported media types, malformed JSON, and invalid payloads", async () => {
  let fetchCalled = false;
  const post = createAuditPostHandler(async () => {
    fetchCalled = true;
    return safeResult;
  });

  const unsupported = await post(request("{}", { headers: { "content-type": "text/plain" } }));
  assert.equal(unsupported.status, 415);

  const malformed = await post(request("{"));
  assert.equal(malformed.status, 400);

  for (const body of ["null", "[]", "{}", JSON.stringify({ url: 123 }), JSON.stringify({ url: " " })]) {
    const response = await post(request(body));
    assert.equal(response.status, 400);
  }
  assert.equal(fetchCalled, false);
});

test("rejects oversized request bodies and excessive URL length", async () => {
  const post = createAuditPostHandler(async () => safeResult);
  const oversized = await post(request(JSON.stringify({ url: "a".repeat(5_000) })));
  assert.equal(oversized.status, 413);

  const excessiveUrl = await post(request(JSON.stringify({ url: `https://${"a".repeat(2_049)}.com` })));
  assert.equal(excessiveUrl.status, 400);
});

test("maps unsafe targets, timeouts, oversized responses, and network failures safely", async () => {
  const cases = [
    [async () => { throw new UnsafeUrlError("private address"); }, 400, "UNSAFE_TARGET", "private address"],
    [async () => { throw new SafeFetchTimeoutError(); }, 504, "TARGET_TIMEOUT", "request exceeded"],
    [async () => { throw new ResponseTooLargeError(); }, 502, "TARGET_RESPONSE_TOO_LARGE", "internal body size"],
    [async () => { throw new Error("secret host detail"); }, 502, "TARGET_UNAVAILABLE", "secret host detail"],
  ];

  for (const [fetchSafeUrl, status, code, privateDetail] of cases) {
    const post = createAuditPostHandler(fetchSafeUrl);
    const response = await post(request(JSON.stringify({ url: "https://shop.example.testdomain.com" })));
    const body = await response.json();
    assert.equal(response.status, status);
    assert.equal(body.error.code, code);
    assert.doesNotMatch(JSON.stringify(body), new RegExp(privateDetail, "i"));
  }
});

test("the route preserves safe-fetch protections for literal and DNS-resolved private targets", async () => {
  let transportCalls = 0;
  const safeFetch = createSafeFetcher({
    resolveHost: async (hostname) =>
      hostname === "private-kaira.testdomain.com"
        ? [{ address: "10.20.30.40", family: 4 }]
        : [{ address: "8.8.8.8", family: 4 }],
    transport: async () => {
      transportCalls += 1;
      return transportResponse(200);
    },
  });
  const post = createAuditPostHandler(safeFetch);

  for (const url of [
    "http://127.0.0.1/admin",
    "https://private-kaira.testdomain.com/secret",
  ]) {
    const response = await post(request(JSON.stringify({ url })));
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "UNSAFE_TARGET");
  }
  assert.equal(transportCalls, 0);
});

test("the route revalidates redirects and does not connect to a private redirect target", async () => {
  const connectedHosts = [];
  const safeFetch = createSafeFetcher({
    resolveHost: async (hostname) =>
      hostname === "private-kaira.testdomain.com"
        ? [{ address: "192.168.1.20", family: 4 }]
        : [{ address: "8.8.8.8", family: 4 }],
    transport: async (url) => {
      connectedHosts.push(url.hostname);
      return transportResponse(302, {
        location: "https://private-kaira.testdomain.com/admin",
      });
    },
  });
  const post = createAuditPostHandler(safeFetch);

  const response = await post(request(JSON.stringify({ url: "https://public-kaira.testdomain.com" })));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "UNSAFE_TARGET");
  assert.deepEqual(connectedHosts, ["public-kaira.testdomain.com"]);
});

test("the route reports findings from the final response after a safe redirect", async () => {
  const safeFetch = createSafeFetcher({
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    transport: async (url) =>
      url.hostname === "start-kaira.testdomain.com"
        ? transportResponse(301, { location: "https://final-kaira.testdomain.com/audit" })
        : transportResponse(200, {
            "content-security-policy": "default-src 'self'; script-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "SAMEORIGIN",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
          }),
  });
  const post = createAuditPostHandler(safeFetch);

  const response = await post(request(JSON.stringify({ url: "http://start-kaira.testdomain.com" })));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.target, "http://start-kaira.testdomain.com");
  assert.equal(body.finalTarget, "https://final-kaira.testdomain.com");
  assert.equal(body.findings.find(({ id }) => id === "transport.https").status, "fail");
  assert.equal(body.findings.find(({ id }) => id === "headers.strict-transport-security").status, "pass");
});

test("the route reports same-origin path redirects without query values or fragments", async () => {
  const safeFetch = createSafeFetcher({
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    transport: async (url) =>
      url.pathname === "/conversation"
        ? transportResponse(302, { location: "/share/42?token=redirect-secret#final-fragment" })
        : transportResponse(200),
  });
  const post = createAuditPostHandler(safeFetch);

  const response = await post(request(JSON.stringify({
    url: "https://same-origin-kaira.testdomain.com/conversation?token=request-secret#request-fragment",
  })));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.requestedUrl, "https://same-origin-kaira.testdomain.com/conversation");
  assert.equal(body.finalUrl, "https://same-origin-kaira.testdomain.com/share/42");
  assert.equal(body.redirected, true);
  assert.equal(body.queryChanged, true);
  assert.doesNotMatch(JSON.stringify(body), /request-secret|redirect-secret|request-fragment|final-fragment/);
});

test("the route reports same-origin query redirects while hiding query values", async () => {
  const safeFetch = createSafeFetcher({
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    transport: async (url) =>
      url.search === "?token=request-secret"
        ? transportResponse(302, { location: "?token=redirect-secret" })
        : transportResponse(200),
  });
  const post = createAuditPostHandler(safeFetch);

  const response = await post(request(JSON.stringify({
    url: "https://same-origin-kaira.testdomain.com/conversation?token=request-secret",
  })));
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.requestedUrl, "https://same-origin-kaira.testdomain.com/conversation");
  assert.equal(body.finalUrl, "https://same-origin-kaira.testdomain.com/conversation");
  assert.equal(body.redirected, true);
  assert.equal(body.queryChanged, true);
  assert.doesNotMatch(JSON.stringify(body), /request-secret|redirect-secret/);
});

test("the route maps a safe-fetch timeout to a generic gateway timeout", async () => {
  const safeFetch = createSafeFetcher({
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    timeoutMs: 10,
    transport: () => new Promise(() => {}),
  });
  const post = createAuditPostHandler(safeFetch);

  const response = await post(request(JSON.stringify({ url: "https://slow-kaira.testdomain.com" })));
  const body = await response.json();
  assert.equal(response.status, 504);
  assert.equal(body.error.code, "TARGET_TIMEOUT");
  assert.doesNotMatch(JSON.stringify(body), /DNS|socket|stack|slow-kaira/);
});