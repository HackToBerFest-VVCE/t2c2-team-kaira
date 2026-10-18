This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.

## Kaira Security Gate

The `Kaira Security Gate` workflow runs on pull requests targeting `main` and on pushes to `main`. Its `Kaira Required Checks` job runs Gitleaks, Semgrep Community security rules, `npm audit`, the test suite, TypeScript, ESLint, and a production build. It uses read-only repository permissions and does not need manually configured credentials. Gitleaks redacts detected values; Semgrep writes its JSON report in the runner workspace and does not upload the source or report.

### Require the check before merging

Repository owners must configure this in GitHub; adding the workflow alone does not make the check mandatory:

1. Open **Settings > Rules > Rulesets** and create or edit a ruleset targeting the `main` branch. A branch protection rule under **Settings > Branches** can be used instead.
2. Require a pull request before merging.
3. Require status checks to pass before merging and select the exact job check **Kaira Required Checks** after it has run at least once.
4. Save the rule. Restrict bypass permissions according to repository policy.

This rule blocks merges to the protected branch when the required job fails. It does not automatically block every deployment: configure each deployment workflow or hosting provider to require the same passing check, and ensure no separate/manual deployment path bypasses that condition. The audit API is not called by this workflow and no URL scanning is performed in CI.

The workflow reports production and full dependency audits separately: `npm audit --omit=dev --audit-level=high` checks production dependencies, and `npm audit --audit-level=high` checks the full tree. A summary compares both JSON reports to identify high-severity findings that are development-only. All three steps are mandatory: a clean production-only result does not hide an unresolved development advisory or make the required check pass. Use `npm explain <package>` to trace a finding to its dependency path. Existing high-severity advisories must be resolved before the required check can pass.
