// Copyright 2026 Thakur Ankush Singh (Vaishnavi Consultant)
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import { chromium } from "playwright-core";

/**
 * Rendering: turn one page of YOUR application into a PDF (and a PNG picture of it) with headless Chromium.
 *
 * Why render inside Papertrust instead of in your app? Because then the signature covers exactly the file
 * Papertrust produced itself; nothing can be swapped between "make the PDF" and "sign the PDF".
 *
 * How your page tells Papertrust it is ready:
 *
 *   <div data-papertrust-sheet data-papertrust-ready="LABEL"> … the document … </div>
 *
 *   - data-papertrust-ready must equal the `label` you sent. This proves the page shows the document you
 *     asked for (and not an error page or a different document).
 *   - data-papertrust-sheet marks the element photographed for the PNG. Without it the whole page is used.
 *
 * Safety:
 *   - Only URLs that start with one of the allowed origins are opened.
 *   - While rendering, every request to any other origin is blocked (data: and blob: URLs are allowed), so a
 *     document page can't load outside scripts, fonts or trackers.
 *   - At most `concurrency` pages render at once; others wait their turn.
 *   - Chromium starts on first use and closes after a few idle minutes to give the memory back.
 */

const CANDIDATES = [
  "/usr/bin/chromium-browser", "/usr/bin/chromium", "/usr/bin/google-chrome",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
];

/** Find a Chromium-family browser: CHROMIUM_PATH first, then the usual install locations. */
export function findChromium(explicit) {
  for (const p of [explicit, ...CANDIDATES].filter(Boolean)) {
    try { if (fs.existsSync(p)) return p; } catch { /* keep looking */ }
  }
  return null;
}

export class RenderError extends Error {}

/**
 * @param {{ origins: string[], chromiumPath: string | null, concurrency?: number, idleMs?: number, timeoutMs?: number }} options
 */
export function createRenderer({ origins, chromiumPath, concurrency = 2, idleMs = 5 * 60_000, timeoutMs = 45_000 }) {
  let browser = null;
  let launching = null;
  let idleTimer = null;
  let active = 0;
  const queue = [];

  const allowed = (url) => origins.some((o) => url === o || url.startsWith(`${o}/`));

  async function getBrowser() {
    if (browser?.isConnected()) return browser;
    if (!chromiumPath) throw new RenderError("Chromium was not found. Install it or set CHROMIUM_PATH.");
    launching ??= chromium.launch({
      executablePath: chromiumPath,
      // inside a container Chromium runs as an unprivileged user without its own sandbox
      args: process.platform === "linux" ? ["--no-sandbox", "--disable-dev-shm-usage", "--font-render-hinting=none"] : [],
    }).then((b) => { browser = b; return b; }).finally(() => { launching = null; });
    return launching;
  }

  async function withSlot(fn) {
    if (active >= concurrency) await new Promise((resolve) => queue.push(resolve));
    active++;
    clearTimeout(idleTimer);
    try {
      return await fn();
    } finally {
      active--;
      queue.shift()?.();
      if (active === 0) {
        idleTimer = setTimeout(() => { void close(); }, idleMs);
        idleTimer.unref(); // an idle browser must not keep the process alive on shutdown
      }
    }
  }

  async function close() {
    clearTimeout(idleTimer);
    const b = browser;
    browser = null;
    await b?.close().catch(() => {});
  }

  /**
   * Render `url` to { pdf, png } (Buffers). Throws RenderError with a readable message when the page can't be
   * used.
   */
  async function render({ url, label }) {
    if (!allowed(url)) throw new RenderError("that URL is not on an allowed origin");
    return withSlot(async () => {
      const context = await (await getBrowser()).newContext({ viewport: { width: 794, height: 1123 }, deviceScaleFactor: 2, colorScheme: "light" });
      try {
        const page = await context.newPage();
        page.setDefaultTimeout(timeoutMs);
        await page.route("**/*", (route) => {
          const u = route.request().url();
          return allowed(u) || u.startsWith("data:") || u.startsWith("blob:") ? route.continue() : route.abort();
        });
        const res = await page.goto(url, { waitUntil: "networkidle", timeout: timeoutMs });
        if (!res || res.status() !== 200) throw new RenderError(`the page answered ${res?.status() ?? "nothing"}`);
        const ready = page.locator(`[data-papertrust-ready="${label}"]`);
        await ready.first().waitFor({ state: "attached", timeout: 10_000 }).catch(() => {});
        if ((await ready.count()) === 0) throw new RenderError("the page is not marked ready for this label (data-papertrust-ready)");
        await page.emulateMedia({ media: "print" });
        const pdf = await page.pdf({ format: "A4", printBackground: true, preferCSSPageSize: true });
        await page.emulateMedia({ media: "screen" });
        const sheet = page.locator("[data-papertrust-sheet]").first();
        const png = (await sheet.count()) ? await sheet.screenshot({ type: "png" }) : await page.screenshot({ type: "png", fullPage: true });
        return { pdf, png };
      } finally {
        await context.close().catch(() => {});
      }
    });
  }

  return { render, close, available: !!chromiumPath && origins.length > 0 };
}
