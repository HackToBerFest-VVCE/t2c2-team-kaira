import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import {
  createNodePinnedTransport,
  createSafeFetcher,
  createPinnedLookup,
  isPublicAddress,
  ResponseTooLargeError,
  SafeFetchTimeoutError,
  UnsafeUrlError,
  validatePublicUrl,
} from "../lib/audits/url-safety.ts";

const publicIpv4 = { address: "8.8.8.8", family: 4 };
const publicIpv6 = { address: "2001:4860:4860::8888", family: 6 };

function response(statusCode, headers = {}, chunks = []) {
  return {
    statusCode,
    headers,
    body: (async function* () {
      for (const chunk of chunks) yield Buffer.from(chunk);
    })(),
    cancel() {},
  };
}

test("accepts HTTP and HTTPS public URLs, rejecting unsafe URL forms", async () => {
  const resolver = async () => [publicIpv4];
  assert.equal((await validatePublicUrl("https://example.com", resolver)).url.protocol, "https:");
  assert.equal((await validatePublicUrl("http://example.com", resolver)).url.protocol, "http:");
  await assert.rejects(validatePublicUrl("http://127.0.0.1", resolver), UnsafeUrlError);
  await assert.rejects(validatePublicUrl("http://[::1]", resolver), UnsafeUrlError);

  for (const input of [
    "ftp://example.com",
    "http://user:pass@example.com",
    "http://example.com:8080",
    "http://localhost",
    "http://host.local",
    "not a URL",
  ]) {
    await assert.rejects(validatePublicUrl(input, resolver), UnsafeUrlError, input);
  }
});

test("rejects private and mixed public/private DNS answers", async () => {
  await assert.rejects(
    validatePublicUrl("https://private.example", async () => [
      { address: "10.1.2.3", family: 4 },
    ]),
    UnsafeUrlError,
  );
  await assert.rejects(
    validatePublicUrl("https://mixed.example", async () => [
      publicIpv4,
      { address: "192.168.1.10", family: 4 },
    ]),
    UnsafeUrlError,
  );
  await assert.rejects(
    validatePublicUrl("https://empty.example", async () => []),
    UnsafeUrlError,
  );
});

test("rejects IPv4 special-use and private ranges", () => {
  for (const address of [
    "0.1.2.3",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.31.255.255",
    "192.0.2.1",
    "192.31.196.1",
    "192.52.193.1",
    "192.168.1.1",
    "192.175.48.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "255.255.255.255",
  ]) {
    assert.equal(isPublicAddress(address, 4), false, address);
  }
  assert.equal(isPublicAddress("8.8.8.8", 4), true);
});

test("rejects the boundaries of every blocked IPv4 prefix", () => {
  const rangeEndpoints = [
    "0.0.0.0", "0.255.255.255",
    "10.0.0.0", "10.255.255.255",
    "100.64.0.0", "100.127.255.255",
    "127.0.0.0", "127.255.255.255",
    "169.254.0.0", "169.254.255.255",
    "172.16.0.0", "172.31.255.255",
    "192.0.0.0", "192.0.0.255",
    "192.0.2.0", "192.0.2.255",
    "192.31.196.0", "192.31.196.255",
    "192.52.193.0", "192.52.193.255",
    "192.88.99.0", "192.88.99.255",
    "192.168.0.0", "192.168.255.255",
    "192.175.48.0", "192.175.48.255",
    "198.18.0.0", "198.19.255.255",
    "198.51.100.0", "198.51.100.255",
    "203.0.113.0", "203.0.113.255",
    "224.0.0.0", "239.255.255.255",
    "240.0.0.0", "255.255.255.255",
  ];

  for (const address of rangeEndpoints) {
    assert.equal(isPublicAddress(address, 4), false, address);
  }
});

test("rejects IPv6 non-public ranges and private IPv4-mapped addresses", () => {
  for (const address of [
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:192.168.1.1",
    "64:ff9b::808:808",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "2002::1",
    "2620:4f:8000::1",
    "3fff::1",
    "ff02::1",
  ]) {
    assert.equal(isPublicAddress(address, 6), false, address);
  }
  assert.equal(isPublicAddress("2001:4860:4860::8888", 6), true);
  assert.equal(isPublicAddress("::ffff:8.8.8.8", 6), true);
  assert.equal(isPublicAddress("::8.8.8.8", 6), false);
});

test("rejects the boundaries of every blocked IPv6 prefix", () => {
  const rangeEndpoints = [
    "::", "::1",
    "64:ff9b::", "64:ff9b:0:0:ffff:ffff:ffff:ffff",
    "64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
    "100::", "100:0:0:0:ffff:ffff:ffff:ffff",
    "2001::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
    "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
    "2002::", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "2620:4f:8000::", "2620:4f:8000:ffff:ffff:ffff:ffff:ffff",
    "3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  ];

  for (const address of rangeEndpoints) {
    assert.equal(isPublicAddress(address, 6), false, address);
  }
});

test("revalidates redirects and rejects a redirect to a private address", async () => {
  const transportCalls = [];
  const resolveHost = async (hostname) =>
    hostname === "private-kaira.testdomain.com" ? [{ address: "10.0.0.8", family: 4 }] : [publicIpv4];
  const fetch = createSafeFetcher({
    resolveHost,
    transport: async (url, address) => {
      transportCalls.push({ hostname: url.hostname, address });
      return response(302, { location: "http://private-kaira.testdomain.com/admin" });
    },
  });

  await assert.rejects(fetch("https://public-kaira.testdomain.com"), UnsafeUrlError);
  assert.deepEqual(transportCalls.map(({ hostname }) => hostname), ["public-kaira.testdomain.com"]);
});

test("pins each connection to a validated address despite later DNS changes", async () => {
  let resolveCount = 0;
  const connectedAddresses = [];
  const fetch = createSafeFetcher({
    resolveHost: async () => {
      resolveCount += 1;
      return [resolveCount === 1 ? publicIpv4 : { address: "127.0.0.1", family: 4 }];
    },
    transport: async (_url, pinnedAddress) => {
      connectedAddresses.push(pinnedAddress.address);
      return response(200, {}, ["ok"]);
    },
  });

  const result = await fetch("https://rebind-kaira.testdomain.com");
  assert.equal(result.body.toString(), "ok");
  assert.deepEqual(connectedAddresses, ["8.8.8.8"]);
  assert.equal(resolveCount, 1);
});

test("follows a public redirect only after resolving and pinning its new host", async () => {
  const connected = [];
  const fetch = createSafeFetcher({
    resolveHost: async (hostname) => [hostname === "second-kaira.testdomain.com" ? publicIpv6 : publicIpv4],
    transport: async (url, address) => {
      connected.push({ hostname: url.hostname, address: address.address });
      return url.hostname === "first-kaira.testdomain.com"
        ? response(302, { location: "https://second-kaira.testdomain.com/result" })
        : response(200, {}, ["done"]);
    },
  });

  const result = await fetch("https://first-kaira.testdomain.com/start");
  assert.equal(result.body.toString(), "done");
  assert.deepEqual(connected, [
    { hostname: "first-kaira.testdomain.com", address: "8.8.8.8" },
    { hostname: "second-kaira.testdomain.com", address: "2001:4860:4860::8888" },
  ]);
});

test("validates and follows redirects across HTTP and HTTPS schemes", async () => {
  for (const [startProtocol, redirectProtocol] of [
    ["http:", "https:"],
    ["https:", "http:"],
  ]) {
    const connectedProtocols = [];
    const fetch = createSafeFetcher({
      resolveHost: async () => [publicIpv4],
      transport: async (url) => {
        connectedProtocols.push(url.protocol);
        return url.pathname === "/start"
          ? response(302, { location: `${redirectProtocol}//redirect-kaira.testdomain.com/final` })
          : response(200, {}, ["ok"]);
      },
    });

    const result = await fetch(`${startProtocol}//origin-kaira.testdomain.com/start`);
    assert.equal(result.body.toString(), "ok");
    assert.deepEqual(connectedProtocols, [startProtocol, redirectProtocol]);
  }
});

test("enforces a bounded redirect count", async () => {
  const fetch = createSafeFetcher({
    resolveHost: async () => [publicIpv4],
    maxRedirects: 1,
    transport: async () => response(302, { location: "/again" }),
  });
  await assert.rejects(fetch("https://example.com"), /redirect loop|redirect limit/i);
});

test("enforces an overall timeout without a real request", async () => {
  const fetch = createSafeFetcher({
    resolveHost: async () => [publicIpv4],
    timeoutMs: 10,
    transport: () => new Promise(() => {}),
  });
  await assert.rejects(fetch("https://example.com"), SafeFetchTimeoutError);
});

test("enforces the response size limit from both headers and streamed bytes", async () => {
  const advertisedTooLarge = createSafeFetcher({
    resolveHost: async () => [publicIpv4],
    maxResponseBytes: 4,
    transport: async () => response(200, { "content-length": "5" }),
  });
  await assert.rejects(advertisedTooLarge("https://example.com"), ResponseTooLargeError);

  const streamedTooLarge = createSafeFetcher({
    resolveHost: async () => [publicIpv4],
    maxResponseBytes: 4,
    transport: async () => response(200, {}, ["123", "45"]),
  });
  await assert.rejects(streamedTooLarge("https://example.com"), ResponseTooLargeError);
});

test("the Node lookup callback returns only the previously validated address", async () => {
  const lookup = createPinnedLookup(publicIpv4);
  const result = await new Promise((resolve, reject) => {
    lookup("rebind-kaira.testdomain.com", {}, (error, address, family) => {
      if (error) reject(error);
      else resolve({ address, family });
    });
  });

  assert.deepEqual(result, publicIpv4);
  assert.throws(
    () => createPinnedLookup({ address: "127.0.0.1", family: 4 }),
    UnsafeUrlError,
  );
});

test("Node HTTP and HTTPS transports use the pinned lookup and preserve host validation", async () => {
  for (const protocol of ["http:", "https:"]) {
    let requestOptions;
    let responseStream;

    const fakeRequest = (options, onResponse) => {
      requestOptions = options;
      const request = new EventEmitter();
      request.destroy = (error) => request.emit("error", error);
      request.end = () => {
        responseStream = new EventEmitter();
        responseStream.statusCode = 200;
        responseStream.headers = {};
        responseStream.destroy = () => responseStream.emit("close");
        responseStream[Symbol.asyncIterator] = async function* () {
          yield Buffer.from("ok");
        };
        onResponse(responseStream);
        request.emit("close");
      };
      return request;
    };

    const transport = createNodePinnedTransport({
      http: fakeRequest,
      https: fakeRequest,
    });
    const result = await transport(
      new URL(`${protocol}//origin-kaira.testdomain.com/path?q=1`),
      publicIpv4,
      new AbortController().signal,
    );

    assert.equal(requestOptions.hostname, "origin-kaira.testdomain.com");
    assert.equal(requestOptions.headers.host, "origin-kaira.testdomain.com");
    assert.equal(requestOptions.agent, false);
    assert.equal(requestOptions.servername, protocol === "https:" ? "origin-kaira.testdomain.com" : undefined);
    const pinned = await new Promise((resolve, reject) => {
      requestOptions.lookup("origin-kaira.testdomain.com", {}, (error, address, family) => {
        if (error) reject(error);
        else resolve({ address, family });
      });
    });
    assert.deepEqual(pinned, publicIpv4);
    assert.equal((await (async () => {
      const chunks = [];
      for await (const chunk of result.body) chunks.push(chunk);
      return Buffer.concat(chunks).toString();
    })()), "ok");
    result.cancel();
  }
});

test("cancels redirect responses with missing or malformed locations", async () => {
  for (const headers of [{}, { location: "http://[invalid" }]) {
    let cancelled = false;
    const fetch = createSafeFetcher({
      resolveHost: async () => [publicIpv4],
      transport: async () => ({
        ...response(302, headers),
        cancel() {
          cancelled = true;
        },
      }),
    });

    await assert.rejects(fetch("https://safe-kaira.testdomain.com"), UnsafeUrlError);
    assert.equal(cancelled, true);
  }
});

test("aborts and cancels a response body that stalls past the timeout", async () => {
  let cancelled = false;
  const fetch = createSafeFetcher({
    resolveHost: async () => [publicIpv4],
    timeoutMs: 10,
    transport: async () => ({
      ...response(200),
      body: (async function* () {
        await new Promise(() => {});
      })(),
      cancel() {
        cancelled = true;
      },
    }),
  });

  await assert.rejects(fetch("https://body-timeout-kaira.testdomain.com"), SafeFetchTimeoutError);
  assert.equal(cancelled, true);
});

test("fails closed on DNS and transport errors", async () => {
  let transportCalled = false;
  const dnsFailure = createSafeFetcher({
    resolveHost: async () => {
      throw new Error("DNS failed");
    },
    transport: async () => {
      transportCalled = true;
      return response(200);
    },
  });
  await assert.rejects(dnsFailure("https://dns-failure-kaira.testdomain.com"), /DNS failed/);
  assert.equal(transportCalled, false);

  const transportFailure = createSafeFetcher({
    resolveHost: async () => [publicIpv4],
    transport: async () => {
      throw new Error("Connection failed");
    },
  });
  await assert.rejects(
    transportFailure("https://transport-failure-kaira.testdomain.com"),
    /Connection failed/,
  );
});