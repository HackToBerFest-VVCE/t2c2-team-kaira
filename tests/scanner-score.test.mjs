import assert from "node:assert/strict";
import test from "node:test";
import { calculateScanCoverage, scoreAudit } from "../lib/audits/scanner-score.ts";

test("keeps the security score separate from the discovered-page coverage ratio", () => {
  const score = scoreAudit([
    { id: "headers.csp", pageUrl: "https://site.test/", severity: "high", status: "fail" },
    { id: "transport.https", pageUrl: "https://site.test/", severity: "high", status: "pass" },
  ]);
  const coverage = calculateScanCoverage({
    pagesScanned: 1,
    pagesFailed: 1,
    pagesOmitted: 3,
    pageLimit: 5,
  });

  assert.equal(score, 80);
  assert.equal(coverage.percentage, 20);
  assert.equal(coverage.label, "Partial coverage");
});

test("shows full coverage when all actually discovered pages were scanned", () => {
  assert.equal(calculateScanCoverage({
    pagesScanned: 1,
    pagesFailed: 0,
    pagesOmitted: 0,
    pageLimit: 5,
  }).percentage, 100);
});
