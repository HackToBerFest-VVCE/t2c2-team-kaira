import assert from "node:assert/strict";
import test from "node:test";
import { auditWebsiteResponse } from "../lib/audits/website-checks.ts";

function audit(headers = {}, requestedUrl = "https://shop.example.testdomain.com", finalUrl = requestedUrl) {
  return auditWebsiteResponse({
    requestedUrl,
    finalUrl,
    statusCode: 200,
    headers,
  });
}

function find(findings, id) {
  const finding = findings.find((item) => item.id === id);
  assert.ok(finding, `missing finding ${id}`);
  return finding;
}

test("reports HTTP use and a redirect that ends on HTTP", () => {
  const findings = audit({}, "http://shop.example.testdomain.com", "http://shop.example.testdomain.com");
  const transport = find(findings, "transport.https");

  assert.equal(transport.status, "fail");
  assert.equal(transport.severity, "medium");
  assert.match(transport.evidence, /http:/);
});

test("checks common security headers and distinguishes missing from weak values", () => {
  const findings = audit({
    "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
    "strict-transport-security": "max-age=60",
    "x-content-type-options": "nosniff",
    "x-frame-options": "SAMEORIGIN",
    "referrer-policy": "unsafe-url",
  });

  assert.equal(find(findings, "headers.content-security-policy").status, "fail");
  assert.match(find(findings, "headers.content-security-policy").explanation, /unsafe-inline/);
  assert.equal(find(findings, "headers.strict-transport-security").status, "fail");
  assert.equal(find(findings, "headers.x-content-type-options").status, "pass");
  assert.equal(find(findings, "headers.frame-options").status, "pass");
  assert.equal(find(findings, "headers.referrer-policy").status, "fail");
  assert.equal(find(findings, "headers.permissions-policy").status, "fail");

  for (const finding of findings) {
    assert.ok(finding.id);
    assert.ok(finding.severity);
    assert.ok(finding.title);
    assert.ok(finding.explanation);
    assert.ok(finding.evidence);
    assert.ok(finding.recommendation);
  }
});

test("marks HSTS not applicable when the final response is HTTP", () => {
  const findings = audit(
    { "strict-transport-security": "max-age=31536000" },
    "https://shop.example.testdomain.com",
    "http://shop.example.testdomain.com",
  );

  assert.equal(find(findings, "headers.strict-transport-security").status, "not_applicable");
  assert.match(find(findings, "headers.strict-transport-security").explanation, /only honor HSTS/);
  assert.equal(find(findings, "transport.https").status, "fail");
});

test("checks cookie flags without returning cookie values", () => {
  const findings = audit({
    "set-cookie": [
      "sessionid=private-value; Path=/; HttpOnly; SameSite=Lax",
      "theme=light; Path=/; Secure; SameSite=Strict",
    ],
  });

  assert.equal(find(findings, "cookies.secure").status, "fail");
  assert.match(find(findings, "cookies.secure").evidence, /sessionid/);
  assert.equal(find(findings, "cookies.httponly").status, "fail");
  assert.equal(find(findings, "cookies.samesite").status, "pass");
  assert.doesNotMatch(JSON.stringify(findings), /private-value/);
  assert.match(find(findings, "cookies.httponly").explanation, /may be intentional/);
});

test("reports cookie checks as not applicable when no cookies are set", () => {
  const findings = audit();
  for (const id of ["cookies.secure", "cookies.httponly", "cookies.samesite"]) {
    assert.equal(find(findings, id).status, "not_applicable");
    assert.match(find(findings, id).explanation, /did not set cookies/);
  }
});

test("describes missing headers as hardening gaps, not confirmed vulnerabilities", () => {
  const findings = audit();
  const missingHeaderIds = [
    "headers.content-security-policy",
    "headers.strict-transport-security",
    "headers.x-content-type-options",
    "headers.frame-options",
    "headers.referrer-policy",
    "headers.permissions-policy",
  ];

  for (const id of missingHeaderIds) {
    const finding = find(findings, id);
    assert.equal(finding.status, "fail");
    assert.match(finding.explanation, /does not by itself prove|not proof/i);
  }
});

test("does not pass a CSP without script policy or wildcard frame restrictions", () => {
  const findings = audit({
    "content-security-policy": "frame-ancestors *",
  });

  assert.equal(find(findings, "headers.content-security-policy").status, "fail");
  assert.equal(find(findings, "headers.frame-options").status, "fail");
  assert.match(find(findings, "headers.frame-options").explanation, /wildcard/);
});

test("flags an empty script-src directive as a weak policy", () => {
  const findings = audit({
    "content-security-policy": "script-src",
  });

  assert.equal(find(findings, "headers.content-security-policy").status, "fail");
});

test("flags SameSite=None cookies that omit Secure", () => {
  const findings = audit({
    "set-cookie": ["cross-site=value; SameSite=None; HttpOnly"],
  });

  assert.equal(find(findings, "cookies.samesite").status, "fail");
  assert.match(find(findings, "cookies.samesite").evidence, /cross-site/);
  assert.doesNotMatch(JSON.stringify(findings), /cross-site=value/);
});