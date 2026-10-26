import assert from "node:assert/strict";
import test from "node:test";
import { scanSameOriginPages } from "../lib/audits/website-crawl.ts";

function response(url, html, statusCode = 200) {
  return {
    url,
    statusCode,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: Buffer.from(html),
  };
}

test("scans the submitted page and bounded same-origin HTML links", async () => {
  const rootUrl = "https://shop.example.testdomain.com/";
  const calls = [];
  const root = response(
    rootUrl,
    '<html><script>const template = \'<a href="/fake-script-link">\';</script>' +
      '<a href="/image.png">Image</a><a href="/account?session=private">Account</a>' +
      '<a href="https://other.example/landing">External</a>' +
      '<a href="/logout">Logout</a></html>',
  );
  const result = await scanSameOriginPages(
    rootUrl,
    root,
    async (url) => {
      calls.push(url);
      return response(url, "<html><body>Account</body></html>");
    },
  );

  assert.equal(result.pagesScanned, 2);
  assert.equal(result.pagesFailed, 0);
  assert.deepEqual(calls, ["https://shop.example.testdomain.com/account"]);
  assert.ok(result.findings.every(({ pageUrl }) => !pageUrl.includes("?")));
  assert.ok(result.findings.every(({ pageUrl }) =>
    pageUrl.startsWith("https://shop.example.testdomain.com/"),
  ));
});

test("checks actual HTML for insecure forms and mixed-content resources", async () => {
  const pageUrl = "https://shop.example.testdomain.com/";
  const result = await scanSameOriginPages(
    pageUrl,
    response(
      pageUrl,
      '<html><form action="http://collect.example.test/submit"></form>' +
        '<img src="http://cdn.example.test/image.png"></html>',
    ),
    async () => {
      throw new Error("No additional pages expected.");
    },
  );

  assert.equal(
    result.findings.find(({ id }) => id === "content.insecure-form")?.status,
    "fail",
  );
  assert.equal(
    result.findings.find(({ id }) => id === "content.mixed-content")?.status,
    "fail",
  );
});

test("caps live requests and reports unreachable same-origin pages without failing the root scan", async () => {
  const pageUrl = "https://shop.example.testdomain.com/";
  const links = Array.from(
    { length: 20 },
    (_, index) => `<a href="/page-${index}">Page</a>`,
  ).join("");
  const calls = [];
  const result = await scanSameOriginPages(
    pageUrl,
    response(pageUrl, `<html>${links}</html>`),
    async (url) => {
      calls.push(url);
      if (url.endsWith("/page-0")) {
        return response(url, "<html>OK</html>");
      }
      throw new Error("Network failure");
    },
  );

  assert.equal(calls.length, 4);
  assert.equal(result.pagesScanned, 2);
  assert.equal(result.pagesFailed, 3);
  assert.equal(result.pagesOmitted, 16);
});
