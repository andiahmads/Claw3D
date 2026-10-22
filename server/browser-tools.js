"use strict";

/**
 * Remote browser tools for Hermes agents.
 *
 * Agents drive a shared Chromium (the `browser` compose service, reached over
 * the Playwright protocol at BROWSER_WS_URL). Each agent gets its own browser
 * context, so cookies and logins persist per agent until browser_close.
 *
 * Secrets never pass through the model: agents type `{{secret:NAME}}` and the
 * value is read from the BROWSER_SECRET_NAME environment variable.
 *
 * Environment variables:
 *   BROWSER_WS_URL          Playwright server endpoint (unset = tools disabled)
 *   BROWSER_SECRET_<NAME>   Values agents may reference as {{secret:NAME}}
 */

const MAX_TEXT_CHARS = 12_000;
const MAX_ELEMENTS = 80;
const ACTION_TIMEOUT_MS = 15_000;
const NAV_TIMEOUT_MS = 45_000;
const IDLE_CLOSE_MS = 30 * 60 * 1000;

const SECRET_RE = /\{\{secret:([A-Z0-9_]+)\}\}/g;

let browserPromise = null;
const sessions = new Map(); // agentId -> { context, page, refs, idleTimer }

const BROWSER_TOOLS = [
  {
    type: "function",
    function: {
      name: "browser_open",
      description:
        "Open a URL in your remote browser (a real Chromium that keeps cookies and logins). " +
        "Returns the page title, visible text, and a numbered list of interactive elements. " +
        "Use this for pages that need login, forms, or JavaScript. For simple public pages prefer fetch_url.",
      parameters: {
        type: "object",
        required: ["url"],
        properties: { url: { type: "string", description: "Full http(s) URL" } },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_snapshot",
      description: "Re-read the current page: title, visible text, and numbered interactive elements.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_click",
      description: "Click an element by its number from the latest snapshot. Returns a fresh snapshot.",
      parameters: {
        type: "object",
        required: ["ref"],
        properties: { ref: { type: "number", description: "Element number, e.g. 3 for [3]" } },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_type",
      description:
        "Fill a text field by its element number. To enter a password or other secret, " +
        "pass {{secret:NAME}} (e.g. {{secret:CMS_PASSWORD}}) instead of the real value; " +
        "never ask the user to send passwords in chat. Set submit=true to press Enter afterwards.",
      parameters: {
        type: "object",
        required: ["ref", "text"],
        properties: {
          ref: { type: "number" },
          text: { type: "string" },
          submit: { type: "boolean", description: "Press Enter after typing. Default false." },
        },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_select",
      description: "Choose an option in a <select> dropdown by its element number and the option's visible label.",
      parameters: {
        type: "object",
        required: ["ref", "option"],
        properties: { ref: { type: "number" }, option: { type: "string" } },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_press",
      description: "Press a keyboard key on the current page, e.g. Enter, Tab, Escape, PageDown.",
      parameters: {
        type: "object",
        required: ["key"],
        properties: { key: { type: "string" } },
      },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_list_secrets",
      description: "List the secret names you may use as {{secret:NAME}}. Values are never shown.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "browser_close",
      description: "Close your browser session and forget its cookies/logins.",
      parameters: { type: "object", properties: {} },
    },
  },
];

const listSecretNames = () =>
  Object.keys(process.env)
    .filter((key) => key.startsWith("BROWSER_SECRET_") && process.env[key])
    .map((key) => key.slice("BROWSER_SECRET_".length));

function resolveSecrets(text) {
  const missing = [];
  const resolved = text.replace(SECRET_RE, (_, name) => {
    const value = process.env[`BROWSER_SECRET_${name}`];
    if (!value) missing.push(name);
    return value || "";
  });
  return { resolved, missing };
}

// Replace any secret value that appears in page output with its placeholder.
function redactSecrets(text) {
  let out = text;
  for (const name of listSecretNames()) {
    const value = process.env[`BROWSER_SECRET_${name}`];
    if (value && value.length >= 4) out = out.split(value).join(`{{secret:${name}}}`);
  }
  return out;
}

async function getBrowser() {
  if (!browserPromise) {
    const { chromium } = require("playwright-core");
    browserPromise = chromium.connect(process.env.BROWSER_WS_URL, { timeout: 30_000 }).then((browser) => {
      browser.on("disconnected", () => {
        browserPromise = null;
        sessions.clear();
      });
      return browser;
    });
    browserPromise.catch(() => {
      browserPromise = null;
    });
  }
  return browserPromise;
}

async function getSession(agentId, assertPublicUrl) {
  let session = sessions.get(agentId);
  if (!session) {
    const browser = await getBrowser();
    const context = await browser.newContext({
      viewport: { width: 1280, height: 900 },
      locale: "id-ID",
    });
    // Same SSRF policy as fetch_url, applied to every request the page makes.
    await context.route("**/*", async (route) => {
      try {
        await assertPublicUrl(new URL(route.request().url()));
        await route.continue();
      } catch {
        await route.abort("blockedbyclient");
      }
    });
    const page = await context.newPage();
    page.setDefaultTimeout(ACTION_TIMEOUT_MS);
    page.setDefaultNavigationTimeout(NAV_TIMEOUT_MS);
    session = { context, page, refs: 0, idleTimer: null };
    sessions.set(agentId, session);
  }
  clearTimeout(session.idleTimer);
  session.idleTimer = setTimeout(() => closeSession(agentId), IDLE_CLOSE_MS);
  session.idleTimer.unref?.();
  return session;
}

async function closeSession(agentId) {
  const session = sessions.get(agentId);
  if (!session) return false;
  sessions.delete(agentId);
  clearTimeout(session.idleTimer);
  await session.context.close().catch(() => {});
  return true;
}

// Number visible interactive elements with data-claw-ref and describe them.
async function snapshot(page) {
  await page.waitForLoadState("domcontentloaded").catch(() => {});
  const result = await page.evaluate(
    ({ maxText, maxElements }) => {
      document.querySelectorAll("[data-claw-ref]").forEach((el) => el.removeAttribute("data-claw-ref"));
      const selector =
        "a[href], button, input:not([type=hidden]), textarea, select, [role=button], [role=link], [role=checkbox], [role=tab], [role=menuitem], [contenteditable=true]";
      const visible = (el) => {
        const rect = el.getBoundingClientRect();
        const style = getComputedStyle(el);
        return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
      };
      const clean = (s) => (s || "").replace(/\s+/g, " ").trim().slice(0, 80);
      const elements = [];
      let n = 0;
      for (const el of document.querySelectorAll(selector)) {
        if (!visible(el) || el.disabled) continue;
        n += 1;
        if (n > maxElements) break;
        el.setAttribute("data-claw-ref", String(n));
        const tag = el.tagName.toLowerCase();
        const type = el.getAttribute("type");
        const kind = tag === "input" ? `input${type ? `:${type}` : ""}` : el.getAttribute("role") || tag;
        const label = clean(
          el.getAttribute("aria-label") ||
            (el.labels && el.labels[0] && el.labels[0].innerText) ||
            el.getAttribute("placeholder") ||
            el.innerText ||
            el.getAttribute("title") ||
            el.getAttribute("name") ||
            el.getAttribute("value")
        );
        let extra = "";
        if (tag === "input" && type === "password") extra = el.value ? " (filled)" : "";
        else if ((tag === "input" || tag === "textarea") && el.value) extra = ` = "${clean(el.value)}"`;
        else if (tag === "select") {
          const opts = [...el.options].map((o) => clean(o.label)).slice(0, 15);
          extra = ` options: ${opts.join(" | ")}`;
        } else if (tag === "a") extra = ` -> ${clean(el.getAttribute("href"))}`;
        elements.push(`[${n}] ${kind} "${label}"${extra}`);
      }
      const text = (document.body ? document.body.innerText : "").replace(/\n\s*\n+/g, "\n\n").trim();
      return {
        title: document.title,
        text: text.slice(0, maxText),
        textTruncated: text.length > maxText,
        elements,
        elementsTruncated: n > maxElements,
      };
    },
    { maxText: MAX_TEXT_CHARS, maxElements: MAX_ELEMENTS }
  );
  return {
    ok: true,
    url: page.url(),
    title: result.title,
    text: redactSecrets(result.text),
    text_truncated: result.textTruncated,
    elements: result.elements.map(redactSecrets),
    elements_truncated: result.elementsTruncated,
  };
}

const locatorFor = (page, ref) => page.locator(`[data-claw-ref="${Number(ref)}"]`).first();

async function afterAction(page) {
  await page.waitForLoadState("domcontentloaded", { timeout: 5_000 }).catch(() => {});
  await page.waitForTimeout(800);
  return snapshot(page);
}

async function runBrowserTool(name, args, { agentId, assertPublicUrl, log }) {
  if (!process.env.BROWSER_WS_URL) {
    return { ok: false, error: "Remote browser is not configured on this server." };
  }
  if (name === "browser_list_secrets") return { ok: true, secrets: listSecretNames() };
  if (name === "browser_close") return { ok: true, closed: await closeSession(agentId) };

  const session = await getSession(agentId, assertPublicUrl);
  const { page } = session;
  switch (name) {
    case "browser_open": {
      const url = new URL(String(args.url || "").trim());
      await assertPublicUrl(url);
      log(`browser_open ${url.hostname}`);
      const res = await page.goto(url.toString(), { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(1_000);
      return { ...(await snapshot(page)), status: res ? res.status() : null };
    }
    case "browser_snapshot":
      return snapshot(page);
    case "browser_click":
      await locatorFor(page, args.ref).click();
      return afterAction(page);
    case "browser_type": {
      const { resolved, missing } = resolveSecrets(String(args.text ?? ""));
      if (missing.length) {
        return { ok: false, error: `Unknown secret(s): ${missing.join(", ")}. Use browser_list_secrets.` };
      }
      const field = locatorFor(page, args.ref);
      await field.fill(resolved);
      if (args.submit) await field.press("Enter");
      return afterAction(page);
    }
    case "browser_select":
      await locatorFor(page, args.ref).selectOption({ label: String(args.option ?? "") });
      return afterAction(page);
    case "browser_press":
      await page.keyboard.press(String(args.key || "Enter"));
      return afterAction(page);
    default:
      return { ok: false, error: `Unknown browser tool: ${name}` };
  }
}

const isBrowserTool = (name) => name.startsWith("browser_");

module.exports = { BROWSER_TOOLS, runBrowserTool, isBrowserTool, redactSecrets };
