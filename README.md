# Vibe Guard (Kaira)

## Project vision

Vibe Guard is a hackathon project exploring an AI-assisted security gatekeeper for web applications. The broader goal is to make security checks understandable and actionable by combining automated checks, risk explanations, remediation guidance, and fix verification.

Project objectives include identifying insecure configurations, detecting exposed secrets and vulnerable dependencies, explaining findings, verifying fixes, and integrating checks into development and deployment workflows. These are project goals; not all are implemented in the current application.

## Current Kaira implementation

The dashboard offers public website checks and exposed-secret checks:

- Website checks evaluate observed HTTP responses and show findings, severity, evidence, and suggested fixes. The configuration score is weighted from observed checks; page coverage is displayed separately and counts discovered pages scanned, failed, and omitted.
- Secret detection inspects public HTML and same-origin JavaScript only. URL validation, DNS pinning, redirect checks, per-request timeouts, response-size caps, and bounded page/resource counts are enforced. Resource failures and timeouts are reported as incomplete rather than clean scans; secret values are redacted.
- Dependency audits are not available in the dashboard. Website URL scans do not infer project dependencies or display dependency findings. CI continues to audit this repository's dependencies with `npm audit`.
- Before/after website comparison is session-only and reports resolved, persisting, and new failed checks only when both scans are for the same website origin.
- Regression tests run the secret detector against labeled fixtures and measure fixture agreement. That measurement is not displayed as real-world accuracy and does not predict detection rates on arbitrary websites.

These are bounded passive checks, not a full vulnerability assessment: authenticated pages, application source, backend behavior, active exploit testing, and unrecognized secret patterns are outside the coverage.

## Technology

- Next.js, React, and TypeScript
- Tailwind CSS
- Node.js API route
- GitHub Actions for the Kaira Security Gate
- Gitleaks, Semgrep Community rules, and `npm audit` in CI

## Local development

Install dependencies and start the development server from the project directory:

```powershell
npm.cmd ci
npm.cmd run dev
```

Open [http://localhost:3000](http://localhost:3000). In PowerShell environments that block script execution, use the Windows `npm.cmd` command shim as shown.

Run tests, lint, type checks, and a production build with:

```powershell
npm.cmd test
npm.cmd run lint
node_modules\.bin\tsc.cmd --noEmit
npm.cmd run build
```

## Kaira Security Gate

The `Kaira Security Gate` workflow runs on pull requests targeting `main` and on pushes to `main`. Its `Kaira Required Checks` job runs Gitleaks, Semgrep Community security rules, `npm audit`, the test suite, TypeScript, ESLint, and a production build. It uses read-only repository permissions and does not need manually configured credentials. Gitleaks redacts detected values; Semgrep writes its JSON report in the runner workspace and does not upload the source or report.

### Require the check before merging

Repository owners must configure this in GitHub; adding the workflow alone does not make the check mandatory:

1. Open **Settings > Rules > Rulesets** and create or edit a ruleset targeting the `main` branch. A branch protection rule under **Settings > Branches** can be used instead.
2. Require a pull request before merging.
3. Require status checks to pass before merging and select the exact job check **Kaira Required Checks** after it has run at least once.
4. Save the rule. Restrict bypass permissions according to repository policy.

This rule blocks merges to the protected branch when the required check fails. It does not automatically block every deployment: configure each deployment workflow or hosting provider to require the same passing check, and ensure no separate/manual deployment path bypasses that condition. The audit API is not called by this workflow and no URL scanning is performed in CI.

The workflow reports production and full dependency audits separately: `npm audit --omit=dev --audit-level=high` checks production dependencies, and `npm audit --audit-level=high` checks the full tree. A summary compares both JSON reports to identify high-severity findings that are development-only. All three steps are mandatory: a clean production-only result does not hide an unresolved development advisory or make the required check pass. Use `npm explain <package>` to trace a finding to its dependency path. Existing high-severity advisories must be resolved before the required check can pass.

## Team

Hackathon team project — Vibe Guard.
