
"use client";

import { FormEvent, useState } from "react";

const featureCards = [
  {
    title: "HTTPS Checks",
    description: "Verify TLS configuration, certificate health, and secure transport settings.",
  },
  {
    title: "Security Headers",
    description: "Spot missing protections like CSP, HSTS, and X-Frame-Options before attack surface expands.",
  },
  {
    title: "Fix Recommendations",
    description: "Get prioritized guidance to reduce risk and improve resilience across your stack.",
  },
];

export default function Home() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState<"idle" | "error" | "ready">("idle");
  const [message, setMessage] = useState(
    "Only scan websites you own or have permission to test."
  );

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();

    const trimmedUrl = url.trim();

    if (!trimmedUrl) {
      setStatus("error");
      setMessage("Enter a website URL to begin the security audit.");
      return;
    }

    try {
      const normalizedUrl = new URL(
        trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")
          ? trimmedUrl
          : `https://${trimmedUrl}`
      );

      if (!["http:", "https:"].includes(normalizedUrl.protocol)) {
        throw new Error("Unsupported protocol");
      }

      setStatus("ready");
      setMessage(`Audit ready for ${normalizedUrl.hostname}. We’ll scan for exposed risks next.`);
    } catch {
      setStatus("error");
      setMessage("Please enter a valid URL, such as https://your-website.com.");
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 text-white">
      <nav className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-sm">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <div>
            <h1 className="text-2xl font-bold text-cyan-400">
              Kaira<span className="text-white">.</span>
            </h1>
            <p className="mt-1 text-sm text-slate-400">AI-Powered Security Auditor</p>
          </div>

          <div className="hidden items-center gap-6 text-sm text-slate-300 md:flex">
            <a href="#features" className="transition hover:text-cyan-300">
              Features
            </a>
            <a href="#scan" className="transition hover:text-cyan-300">
              Scan
            </a>
            <button
              type="button"
              className="rounded-full border border-cyan-400/40 bg-cyan-400/10 px-4 py-2 font-medium text-cyan-300 transition hover:border-cyan-300 hover:bg-cyan-400/20"
            >
              Book Demo
            </button>
          </div>
        </div>
      </nav>

      <section className="mx-auto grid max-w-6xl gap-12 px-6 py-16 md:grid-cols-[1.2fr_0.8fr] md:py-24">
        <div>
          <p className="mb-4 text-sm font-semibold uppercase tracking-[0.22em] text-cyan-400">
            Website Security Analysis
          </p>

          <h2 className="max-w-xl text-4xl font-black leading-tight text-white md:text-6xl">
            Find vulnerabilities.
            <span className="block text-cyan-400">Build with confidence.</span>
          </h2>

          <p className="mt-5 max-w-xl text-base leading-7 text-slate-400 md:text-lg">
            Check your website for common security issues and get clear recommendations to fix them before they become critical problems.
          </p>

          <form id="scan" onSubmit={handleSubmit} className="mt-10 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-2xl shadow-cyan-950/20">
            <label htmlFor="website" className="mb-3 block text-sm font-medium text-slate-200">
              Website URL
            </label>

            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                id="website"
                type="text"
                inputMode="url"
                placeholder="https://your-website.com"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3.5 text-base text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20"
              />

              <button
                type="submit"
                className="rounded-xl bg-cyan-400 px-5 py-3.5 text-base font-bold text-slate-950 transition hover:bg-cyan-300"
              >
                Start Audit
              </button>
            </div>

            <p
              className={`mt-4 text-sm ${
                status === "error" ? "text-rose-400" : status === "ready" ? "text-emerald-400" : "text-slate-500"
              }`}
            >
              {message}
            </p>
          </form>
        </div>

        <div className="flex items-center justify-center">
          <div className="w-full max-w-md rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950 p-6 shadow-2xl shadow-cyan-950/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Security score</p>
                <p className="mt-3 text-4xl font-black text-white">92</p>
              </div>
              <div className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-sm font-semibold text-emerald-300">
                Healthy
              </div>
            </div>

            <div className="mt-8 space-y-4">
              {[
                ["TLS / SSL", "Secure"],
                ["Headers", "Strong"],
                ["Exposure", "Low risk"],
              ].map(([label, value]) => (
                <div key={label} className="rounded-xl border border-slate-800 bg-slate-900/80 p-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-300">{label}</span>
                    <span className="font-semibold text-cyan-300">{value}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-8 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
              <p className="text-sm text-cyan-200">Recommended next action</p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                Enable a strict Content Security Policy and validate cookie security settings before production rollout.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section id="features" className="mx-auto max-w-6xl px-6 pb-20">
        <div className="mb-8 flex items-end justify-between gap-4">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-400">Core checks</p>
            <h3 className="mt-2 text-3xl font-bold text-white">Security coverage that keeps pace</h3>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          {featureCards.map((feature) => (
            <article key={feature.title} className="rounded-2xl border border-slate-800 bg-slate-900 p-6 transition hover:border-cyan-400/50 hover:bg-slate-900/90">
              <div className="mb-4 inline-flex rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-2 text-cyan-300">
                <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <path d="M12 3l7 4v5c0 4.5-2.9 8.7-7 10-4.1-1.3-7-5.5-7-10V7l7-4z" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M9.5 12.5l1.5 1.5 3.5-4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <h4 className="text-xl font-semibold text-white">{feature.title}</h4>
              <p className="mt-3 text-sm leading-6 text-slate-400">{feature.description}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
