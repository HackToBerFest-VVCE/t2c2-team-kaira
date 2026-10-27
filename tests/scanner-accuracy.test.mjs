import assert from "node:assert/strict";
import test from "node:test";
import { calculateScannerAccuracy } from "../lib/audits/scanner-accuracy.ts";
import { detectSecrets } from "../lib/audits/secret-scanner.ts";

const labeledFixtures = [
  {
    name: "API key pattern",
    expectedDetected: true,
    content: 'const apiKey = "fixture-secret-value-123456";',
  },
  {
    name: "private key pattern",
    expectedDetected: true,
    content: "-----BEGIN RSA PRIVATE KEY-----",
  },
  {
    name: "placeholder value",
    expectedDetected: false,
    content: 'const apiKey = "your_api_key_here";',
  },
  {
    name: "ordinary page content",
    expectedDetected: false,
    content: "A normal page with no credential-like values.",
  },
];

test("measures secret-pattern agreement by executing the detector on labeled fixtures", () => {
  const measuredCases = labeledFixtures.map((fixture) => ({
    expectedDetected: fixture.expectedDetected,
    observedDetected: detectSecrets(fixture.content, "fixture.js").length > 0,
  }));
  const result = calculateScannerAccuracy(measuredCases);

  assert.deepEqual(result, {
    total: labeledFixtures.length,
    correct: 4,
    incorrect: 0,
    accuracyPercent: 100,
  });
});

test("does not report a percentage when no labeled scanner cases were run", () => {
  assert.deepEqual(calculateScannerAccuracy([]), {
    total: 0,
    correct: 0,
    incorrect: 0,
    accuracyPercent: null,
  });
});
