import assert from "node:assert/strict";
import test from "node:test";
import {
  classifyNpmCommandError,
  DependencyAuditError,
  formatDependencyFindings,
  parseNpmAuditReport,
} from "../lib/audits/dependency-audit.ts";

test("parses an npm report with zero production vulnerabilities", () => {
  const report = parseNpmAuditReport(JSON.stringify({
    metadata: {
      vulnerabilities: {
        total: 0,
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
      },
    },
    vulnerabilities: {},
  }));

  assert.equal(report.metadata.vulnerabilities.total, 0);
  assert.deepEqual(formatDependencyFindings(report.vulnerabilities), []);
});

test("formats affected packages, severities, advisories, and available fixes", () => {
  const findings = formatDependencyFindings({
    "sample-package": {
      severity: "high",
      isDirect: true,
      range: "<2.0.0",
      fixAvailable: {
        name: "sample-package",
        version: "2.0.0",
        isSemVerMajor: true,
      },
      via: [{
        title: "A sample advisory",
        url: "https://example.test/advisory",
      }],
    },
  });

  assert.deepEqual(findings, [{
    package: "sample-package",
    severity: "high",
    direct: true,
    affectedRange: "<2.0.0",
    fixAvailable: true,
    fix: {
      name: "sample-package",
      version: "2.0.0",
      isSemVerMajor: true,
    },
    advisory: [{
      title: "A sample advisory",
      url: "https://example.test/advisory",
    }],
  }]);
});

test("reports invalid and incomplete npm JSON as audit output errors", () => {
  for (const stdout of ["not-json", "{}", "[]"]) {
    assert.throws(
      () => parseNpmAuditReport(stdout),
      (error) => error instanceof DependencyAuditError && error.status === 502,
    );
  }
});

test("converts npm JSON errors into clear dependency scan errors", () => {
  assert.throws(
    () => parseNpmAuditReport(JSON.stringify({
      error: {
        code: "ENOLOCK",
        summary: "This command requires an existing lockfile.",
      },
    })),
    /This command requires an existing lockfile/,
  );

  assert.throws(
    () => parseNpmAuditReport(JSON.stringify({
      error: {
        code: "ENOTFOUND",
        summary: "request to registry failed",
      },
    })),
    (error) => error instanceof DependencyAuditError && error.status === 502,
  );
});

test("maps process timeouts, network failures, and missing npm to clear errors", () => {
  const timeout = classifyNpmCommandError({
    killed: true,
    signal: "SIGTERM",
  });
  const network = classifyNpmCommandError({
    code: 1,
    stderr: "getaddrinfo ENOTFOUND registry.npmjs.org",
  });
  const missingNpm = classifyNpmCommandError({ code: "ENOENT" });

  assert.equal(timeout.status, 504);
  assert.match(timeout.message, /timed out/i);
  assert.equal(network.status, 502);
  assert.match(network.message, /package registry/i);
  assert.equal(missingNpm.status, 500);
  assert.match(missingNpm.message, /npm was not found/i);
});
