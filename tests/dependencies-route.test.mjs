import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  classifyNpmCommandError,
  DependencyAuditError,
  formatDependencyFindings,
  parseNpmAuditReport,
  validateDependencyProject,
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
    installedVersion: [],
    locations: [],
    vulnerabilityId: "advisory",
    severity: "high",
    direct: true,
    affectedRange: "<2.0.0",
    fixAvailable: true,
    recommendedVersion: "2.0.0",
    fix: {
      name: "sample-package",
      version: "2.0.0",
      isSemVerMajor: true,
    },
    advisory: [{
      title: "A sample advisory",
      url: "https://example.test/advisory",
      source: undefined,
      severity: undefined,
    }],
  }]);
});

test("validates real npm project files and reports project-specific locked versions", async (t) => {
  const projectA = await mkdtemp(path.join(os.tmpdir(), "vibe-deps-a-"));
  const projectB = await mkdtemp(path.join(os.tmpdir(), "vibe-deps-b-"));
  t.after(() => Promise.all([
    rm(projectA, { recursive: true, force: true }),
    rm(projectB, { recursive: true, force: true }),
  ]));
  const manifestA = JSON.stringify({ name: "project-a", dependencies: { "sample-package": "^1.0.0" } });
  const manifestB = JSON.stringify({ name: "project-b", dependencies: { "sample-package": "^2.0.0" } });
  await Promise.all([
    writeFile(path.join(projectA, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/sample-package": { version: "1.2.3" } },
    })),
    writeFile(path.join(projectB, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/sample-package": { version: "2.4.5" } },
    })),
  ]);
  const vulnerability = {
    "sample-package": {
      severity: "high",
      nodes: ["node_modules/sample-package"],
      via: [{ source: 1234, title: "Verified advisory", url: "https://example.test/advisory" }],
    },
  };
  const findingsA = formatDependencyFindings(vulnerability, projectA);
  const findingsB = formatDependencyFindings(vulnerability, projectB);

  assert.equal(validateDependencyProject(manifestA, await readFile(path.join(projectA, "package-lock.json"), "utf8")).name, "project-a");
  assert.equal(validateDependencyProject(manifestB, await readFile(path.join(projectB, "package-lock.json"), "utf8")).name, "project-b");
  assert.deepEqual(findingsA[0].installedVersion, ["1.2.3"]);
  assert.deepEqual(findingsB[0].installedVersion, ["2.4.5"]);
  assert.deepEqual(findingsA[0].locations, ["node_modules/sample-package"]);
  assert.notDeepEqual(findingsA, findingsB);
});

test("rejects malformed or unsupported uploaded dependency files", () => {
  assert.throws(
    () => validateDependencyProject("{}", "{}"),
    (error) => error instanceof DependencyAuditError && error.status === 400,
  );
  assert.throws(
    () => validateDependencyProject("not-json", "{}"),
    (error) => error instanceof DependencyAuditError && error.status === 400,
  );
  assert.throws(
    () => validateDependencyProject(
      JSON.stringify({ dependencies: { "missing-package": "^1.0.0" } }),
      JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }),
    ),
    (error) => error instanceof DependencyAuditError && /lockfile is missing declared package/i.test(error.message),
  );
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
