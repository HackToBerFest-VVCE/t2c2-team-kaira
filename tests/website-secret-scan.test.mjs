import assert from "node:assert/strict";
import test from "node:test";
import { scanWebsiteSecrets } from "../lib/audits/website-secret-scan.ts";
import { createSafeFetcher } from "../lib/audits/url-safety.ts";

function response(url, body, contentType = "text/html", statusCode = 200) {
  return {
    url,
    statusCode,
    headers: { "content-type": contentType },
    body: Buffer.from(body),
  };
}

test("scans actual HTML and same-origin JavaScript while redacting matched secrets", async () => {
  const root = "https://site.example.testdomain.com/";
  const jsUrl = "https://site.example.testdomain.com/assets/app.js";
  const calls = [];
  const result = await scanWebsiteSecrets(root, async (url) => {
    calls.push(url);
    if (url === root) {
      return response(
        root,
        '<html><script src="/assets/app.js"></script>' +
          '<script>const template = \'<a href="/fake-script-link">\';</script>' +
          '<a href="/image.png">Image</a><a href="/account">Account</a></html>',
      );
    }
    if (url === jsUrl) {
      return response(
        jsUrl,
        'const apiKey = "api-secret-from-response";',
        "application/javascript",
      );
    }
    return response(url, "<html>Account page</html>");
  });

  assert.equal(result.summary.total, 1);
  assert.deepEqual(result.findings, [{
    type: "API key",
    resource: "site.example.testdomain.com/assets/app.js",
    line: 1,
    severity: "high",
  }]);
  assert.equal(result.complete, true);
  assert.equal(result.pagesScanned, 2);
  assert.ok(calls.includes(root));
  assert.ok(calls.includes(jsUrl));
  assert.doesNotMatch(JSON.stringify(result), /api-secret-from-response/);
});

test("reports unsuccessful pages and inaccessible scripts instead of claiming a complete scan", async () => {
  const root = "https://site.example.testdomain.com/";
  const result = await scanWebsiteSecrets(root, async (url) => {
    if (url === root) {
      return response(
        root,
        '<html><script src="/assets/unavailable.js"></script></html>',
      );
    }
    throw new Error("private transport information");
  });

  assert.equal(result.complete, false);
  assert.equal(
    result.checks.find(({ kind }) => kind === "JavaScript")?.status,
    "failed",
  );
  assert.equal(result.resourcesFailed, 1);
  assert.doesNotMatch(JSON.stringify(result), /private transport information/);
});

test("rejects unsupported or unreachable root responses rather than reporting no secrets", async () => {
  const failed = scanWebsiteSecrets(
    "https://site.example.testdomain.com/",
    async () => {
      throw new Error("network failure");
    },
  );

  await assert.rejects(failed, /could not be fetched safely/i);
});

test("deduplicates the same detected secret across HTML and JavaScript resources", async () => {
  const root = "https://site.example.testdomain.com/";
  const jsUrl = "https://site.example.testdomain.com/app.js";
  const secret = "shared-secret-value-123";
  const result = await scanWebsiteSecrets(root, async (url) => {
    if (url === root) {
      return response(root, `<html>const apiKey = "${secret}";<script src="/app.js"></script></html>`);
    }
    return response(jsUrl, `const apiKey = "${secret}";`, "application/javascript");
  });

  assert.equal(result.summary.total, 1);
  assert.equal(result.findings.length, 1);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test("does not inspect non-success HTML or JavaScript response bodies", async () => {
  const root = "https://site.example.testdomain.com/";
  const jsUrl = "https://site.example.testdomain.com/missing.js";
  const secret = "must-not-be-scanned-123";
  const result = await scanWebsiteSecrets(root, async (url) => {
    if (url === root) {
      return response(root, '<html><script src="/missing.js"></script></html>');
    }
    return response(jsUrl, `const apiKey = "${secret}";`, "application/javascript", 503);
  });

  const javascriptCheck = result.checks.find(({ kind }) => kind === "JavaScript");
  assert.equal(javascriptCheck.status, "failed");
  assert.equal(javascriptCheck.httpStatus, 503);
  assert.match(javascriptCheck.message, /body was not scanned/i);
  assert.equal(result.resourcesFailed, 1);
  assert.equal(result.findings.length, 0);
  assert.equal(result.complete, false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test("skips HTML and JavaScript bodies with unsupported or missing content types", async () => {
  const root = "https://site.example.testdomain.com/";
  const pageUrl = "https://site.example.testdomain.com/account";
  const jsUrl = "https://site.example.testdomain.com/app.js";
  const secret = "unsupported-body-secret-123";
  const result = await scanWebsiteSecrets(root, async (url) => {
    if (url === root) {
      return response(
        root,
        '<html><a href="/account">Account</a><script src="/app.js"></script></html>',
      );
    }
    if (url === pageUrl) {
      return response(pageUrl, `const apiKey = "${secret}";`, "application/json");
    }
    return response(jsUrl, `const apiKey = "${secret}";`, "text/plain");
  });

  assert.equal(result.findings.length, 0);
  assert.equal(result.complete, false);
  assert.ok(result.checks.some(({ status, message }) =>
    status === "skipped" && /content type.*not supported as HTML/i.test(message)));
  assert.ok(result.checks.some(({ kind, status, message }) =>
    kind === "JavaScript" && status === "skipped" &&
    /content type.*not supported as JavaScript/i.test(message)));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));

  await assert.rejects(
    scanWebsiteSecrets(root, async () =>
      response(root, `const apiKey = "${secret}";`, "application/json")),
    (error) => {
      assert.match(error.message, /did not return a supported HTML content type.*body was not scanned/i);
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    },
  );
});

test("rejects unsuccessful and invalid root HTTP statuses without scanning their bodies", async () => {
  const root = "https://site.example.testdomain.com/";
  const secret = "error-body-secret-123";

  await assert.rejects(
    scanWebsiteSecrets(root, async () =>
      response(root, `<html>const apiKey = "${secret}";</html>`, "text/html", 503)),
    (error) => {
      assert.match(error.message, /unsuccessful HTTP 503.*body was not scanned/i);
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    },
  );
  await assert.rejects(
    scanWebsiteSecrets(root, async () => ({
      ...response(root, `<html>const apiKey = "${secret}";</html>`),
      statusCode: 700,
    })),
    (error) => {
      assert.match(error.message, /unsuccessful response.*body was not scanned/i);
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    },
  );
});

test("reports timeouts without leaking transport errors or secret values", async () => {
  const root = "https://site.example.testdomain.com/";
  const secret = "timeout-body-secret-123";
  const result = await scanWebsiteSecrets(root, async (url) => {
    if (url === root) {
      return response(root, '<html><script src="/slow.js"></script></html>');
    }
    const error = new Error(`timeout contained ${secret}`);
    error.name = "SafeFetchTimeoutError";
    throw error;
  });

  const timeoutCheck = result.checks.find(({ resource }) =>
    resource.endsWith("/slow.js"));
  assert.equal(timeoutCheck.status, "failed");
  assert.equal(timeoutCheck.message, "The resource request timed out.");
  assert.equal(result.resourcesFailed, 1);
  assert.equal(result.complete, false);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test("blocks an external root redirect before requesting its destination", async () => {
  const root = "https://site.example.testdomain.com/";
  const requestedUrls = [];
  const fetcher = createSafeFetcher({
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    transport: async (url) => {
      requestedUrls.push(url.href);
      return {
        statusCode: 302,
        headers: { location: "https://external.example/private" },
        body: (async function* () {})(),
        cancel() {},
      };
    },
    sameOriginRedirectsOnly: true,
  });

  await assert.rejects(
    scanWebsiteSecrets(root, fetcher),
    /redirected outside the scanned origin.*destination was not requested/i,
  );
  assert.deepEqual(requestedUrls, [root]);
});

test("reports blocked external resource redirects as failed without following them", async () => {
  const root = "https://site.example.testdomain.com/";
  const account = "https://site.example.testdomain.com/account";
  const requestedUrls = [];
  const fetcher = createSafeFetcher({
    resolveHost: async () => [{ address: "8.8.8.8", family: 4 }],
    transport: async (url) => {
      requestedUrls.push(url.href);
      if (url.href === root) {
        return {
          statusCode: 200,
          headers: { "content-type": "text/html" },
          body: (async function* () {
            yield Buffer.from('<html><a href="/account">Account</a></html>');
          })(),
          cancel() {},
        };
      }
      return {
        statusCode: 302,
        headers: { location: "https://external.example/private" },
        body: (async function* () {})(),
        cancel() {},
      };
    },
    sameOriginRedirectsOnly: true,
  });

  const result = await scanWebsiteSecrets(root, fetcher);

  assert.deepEqual(requestedUrls, [root, account]);
  assert.equal(result.resourcesScanned, 1);
  assert.equal(result.resourcesFailed, 1);
  assert.equal(result.resourcesSkipped, 0);
  assert.equal(result.complete, false);
  assert.match(
    result.checks.find(({ resource }) => resource.endsWith("/account")).message,
    /destination was not requested/i,
  );
});

test("reports accurate scanned, failed, and skipped counts when resource limits apply", async () => {
  const root = "https://site.example.testdomain.com/";
  const scriptTags = Array.from(
    { length: 12 },
    (_, index) => `<script src="/assets/${index}.js"></script>`,
  ).join("");
  const pageLinks = Array.from(
    { length: 7 },
    (_, index) => `<a href="/page/${index}">Page ${index}</a>`,
  ).join("");

  const result = await scanWebsiteSecrets(root, async (url) => {
    if (url === root) {
      return response(root, `<html>${scriptTags}${pageLinks}</html>`);
    }
    if (new URL(url).pathname.endsWith(".js")) {
      return response(url, "const ready = true;", "application/javascript");
    }
    return response(url, "<html>Page</html>");
  });

  assert.equal(result.resourcesScanned, 15);
  assert.equal(result.resourcesFailed, 0);
  assert.equal(result.resourcesSkipped, 0);
  assert.equal(result.resourcesOmitted, 5);
  assert.equal(result.resourcesExternal, 0);
  assert.equal(result.pagesScanned, 5);
  assert.equal(result.pagesFailed, 0);
  assert.equal(result.complete, false);
  assert.equal(
    result.checks.filter(({ status }) => status === "scanned").length,
    15,
  );
  assert.equal(
    result.checks.filter(({ status }) => status === "omitted").length,
    5,
  );
  assert.ok(result.checks
    .filter(({ status }) => status === "omitted")
    .every(({ message }) => /limit was reached/i.test(message)));
});

test("excludes external scripts from skipped and scanned counts without fetching them", async () => {
  const root = "https://site.example.testdomain.com/";
  const requested = [];
  const result = await scanWebsiteSecrets(root, async (url) => {
    requested.push(url);
    return response(
      root,
      '<html><script src="https://cdn.example.test/app.js"></script>' +
        '<script src="https://assets.example.test/vendor.js"></script></html>',
    );
  });

  assert.deepEqual(requested, [root]);
  assert.equal(result.resourcesScanned, 1);
  assert.equal(result.resourcesFailed, 0);
  assert.equal(result.resourcesSkipped, 0);
  assert.equal(result.resourcesOmitted, 0);
  assert.equal(result.resourcesExternal, 2);
  assert.equal(result.complete, true);
  const externalCheck = result.checks.find(({ status }) => status === "external");
  assert.equal(externalCheck.count, 2);
  assert.match(externalCheck.message, /outside the same-origin scan scope.*not requested/i);
});

test("accounts for per-page HTML discovery limits separately from skipped resources", async () => {
  const root = "https://site.example.testdomain.com/";
  const links = Array.from(
    { length: 60 },
    (_, index) => `<a href="/page/${index}">Page ${index}</a>`,
  ).join("");
  const result = await scanWebsiteSecrets(root, async (url) =>
    response(url, url === root ? `<html>${links}</html>` : "<html>Page</html>"));

  assert.equal(result.pagesScanned, 5);
  assert.equal(result.resourcesScanned, 5);
  assert.equal(result.resourcesFailed, 0);
  assert.equal(result.resourcesSkipped, 0);
  assert.equal(result.resourcesOmitted, 56);
  assert.ok(result.checks
    .filter(({ status }) => status === "omitted")
    .some(({ message }) => /per-page HTML link discovery limit/i.test(message)));
  assert.ok(result.checks
    .filter(({ status }) => status === "omitted")
    .some(({ message }) => /overall HTML page limit/i.test(message)));
});
