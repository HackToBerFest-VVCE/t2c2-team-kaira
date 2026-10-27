import assert from "node:assert/strict";
import test from "node:test";
import { compareAuditFindings } from "../lib/audits/audit-comparison.ts";

const prior = [
  { id: "headers.csp", pageUrl: "https://site.test/a?old=1", status: "fail", title: "Content policy" },
  { id: "cookies.secure", pageUrl: "https://site.test/a", status: "fail", title: "Secure cookie" },
];
const latest = [
  { id: "headers.csp", pageUrl: "https://site.test/a?new=2", status: "pass", title: "Content policy" },
  { id: "cookies.secure", pageUrl: "https://site.test/a", status: "fail", title: "Secure cookie" },
  { id: "transport.https", pageUrl: "https://site.test/a", status: "fail", title: "HTTPS" },
];

test("compares changed checks only for the same website and ignores query strings", () => {
  const result = compareAuditFindings(
    "https://site.test/old",
    "https://site.test/new",
    prior,
    latest,
  );
  assert.equal(result.resolved.length, 1);
  assert.equal(result.persisting.length, 1);
  assert.equal(result.newFindings.length, 1);
});

test("does not compare unrelated websites", () => {
  assert.equal(
    compareAuditFindings("https://one.test/", "https://two.test/", prior, latest),
    null,
  );
});
