import { chromium } from "playwright";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const port = 8011;
const base = `http://127.0.0.1:${port}`;
let backend;

function startBackend() {
  backend = spawn("python", [path.join(root, "backend", "server.py"), "--port", String(port)], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"],
  });
  backend.stdout.on("data", () => {});
  backend.stderr.on("data", () => {});
  return backend;
}

async function stopBackend() {
  if (!backend || backend.exitCode !== null) return;
  backend.kill();
  await new Promise((resolve) => {
    const timer = setTimeout(resolve, 2500);
    backend.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}
async function waitHealthy(timeoutMs = 7000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}/api/health`);
      if (res.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 120));
  }
  throw new Error("backend did not become healthy");
}

async function expectText(locator, text, timeout = 5000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if ((await locator.textContent())?.includes(text)) return;
    await new Promise((r) => setTimeout(r, 120));
  }
  throw new Error(`Expected text "${text}" not found`);
}

startBackend();
await waitHealthy();

const browser = await chromium.launch({ headless: true, channel: "chrome" });
const page = await browser.newPage();
const consoleErrors = [];
const pageErrors = [];
let intentionalOutage = false;

page.on("console", (msg) => {
  if (msg.type() === "error" && !intentionalOutage) consoleErrors.push(msg.text());
});
page.on("pageerror", (err) => pageErrors.push(err.message));
try {
  await page.goto(base, { waitUntil: "domcontentloaded" });
  await expectText(page.locator("body"), "CONNECTED");
  await expectText(page.locator("body"), "AutoShield Edge AI");

  await page.getByTestId("scenario-normal").click();
  await page.waitForTimeout(250);
  await page.getByTestId("start-stop").click();
  await page.waitForTimeout(900);
  await expectText(page.getByTestId("incident-count"), "0 total");
  const livePackets = await page.locator(".can-packet-dot").count();
  if (livePackets < 10) throw new Error(`Expected animated CAN packet flow, found ${livePackets} packets`);
  await expectText(page.getByTestId("can-activity-layer"), "LIVE CAN MESSAGE FLOW");
  await page.getByTestId("start-stop").click();
  await page.waitForTimeout(350);
  if (await page.locator(".can-packet-dot").count()) throw new Error("CAN packets still rendered after Stop");
  await page.getByTestId("reset").click();

  const attacks = [
    ["dos", "RATE_LIMIT_EXCEEDED"],
    ["fuzzy", "UNKNOWN_ID"],
    ["rpm", "ML_RPM"],
    ["gear", "ML_GEAR"],
  ];
  for (const [scenario, evidence] of attacks) {
    await page.getByTestId(`scenario-${scenario}`).click();
    await page.waitForTimeout(250);
    await page.getByTestId("start-stop").click();
    await page.getByTestId("incident-row").first().waitFor({ state: "visible", timeout: 3000 });
    await expectText(page.getByTestId("incident-log"), evidence);
    await page.getByTestId("start-stop").click();
    await page.getByTestId("reset").click();
  }

  await page.getByTestId("scenario-mix").click();
  await page.waitForTimeout(250);
  await page.getByTestId("start-stop").click();
  await expectText(page.getByTestId("incident-log"), "RATE_LIMIT_EXCEEDED", 5000);
  await expectText(page.getByTestId("incident-log"), "UNKNOWN_ID", 5000);
  await expectText(page.getByTestId("incident-log"), "ML_RPM", 5000);
  await expectText(page.getByTestId("incident-log"), "ML_GEAR", 5000);
  const mixedPackets = await page.locator(".can-packet-dot").count();
  if (mixedPackets < 25) throw new Error(`Expected dense mixed-attack animation, found ${mixedPackets} packets`);
  await page.getByTestId("start-stop").click();
  await page.getByTestId("reset").click();

  if (consoleErrors.length) throw new Error(`Unexpected console errors: ${consoleErrors.join(" | ")}`);
  if (pageErrors.length) throw new Error(`Page errors: ${pageErrors.join(" | ")}`);
  intentionalOutage = true;
  await stopBackend();
  await expectText(page.locator("body"), "RECONNECTING", 5000);
  startBackend();
  await waitHealthy();
  await expectText(page.locator("body"), "CONNECTED", 7000);
  intentionalOutage = false;

  console.log("BROWSER_CHECK_PASS");
  console.log("scenarios=normal,dos,fuzzy,rpm,gear,mix");
  console.log("reconnection=pass");
  console.log("console_validation=pass");
  console.log("can_animation=pass");
  console.log("mix_combo=pass");
} finally {
  await browser.close();
  await stopBackend();
}
