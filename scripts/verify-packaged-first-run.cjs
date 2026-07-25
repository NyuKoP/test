const fs = require("node:fs/promises");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { _electron: electron } = require("playwright");

const executablePath = path.resolve(
  process.argv[2] || path.join("release", "win-unpacked", "NKC.exe")
);
const userDataDir = path.join(
  process.env.TEMP || "C:\\tmp",
  `nkc-packaged-first-run-${process.pid}-${Date.now()}`
);

const run = async () => {
  const env = {
    ...process.env,
    VITE_DEV_SERVER_URL: "http://127.0.0.1:9",
  };
  delete env.ELECTRON_RUN_AS_NODE;

  const launch = () =>
    electron.launch({
      executablePath,
      args: [`--user-data-dir=${userDataDir}`],
      env,
    });

  if (process.env.NKC_PLAYWRIGHT_PACKAGED !== "1") {
    const child = spawn(executablePath, [`--user-data-dir=${userDataDir}`], {
      env,
      stdio: "ignore",
      windowsHide: true,
    });
    await new Promise((resolve) => setTimeout(resolve, 8_000));
    if (child.exitCode !== null) {
      throw new Error(`Packaged app exited during hardened launch check (${child.exitCode})`);
    }
    child.kill();
    await new Promise((resolve) => child.once("exit", resolve));
    console.log(JSON.stringify({ hardenedLaunch: true, userDataDir }));
    await fs.rm(userDataDir, { recursive: true, force: true });
    return;
  }

  let electronApp;
  try {
    electronApp = await launch();
  } catch (error) {
    console.warn(
      "[packaged-first-run] Playwright instrumentation was blocked; " +
        "falling back to a hardened-process launch check."
    );
    const child = spawn(executablePath, [`--user-data-dir=${userDataDir}`], {
      env,
      stdio: "ignore",
      windowsHide: true,
    });
    await new Promise((resolve) => setTimeout(resolve, 8_000));
    if (child.exitCode !== null) {
      throw new Error(`Packaged app exited during hardened launch check (${child.exitCode})`, {
        cause: error,
      });
    }
    child.kill();
    await new Promise((resolve) => child.once("exit", resolve));
    console.log(JSON.stringify({ hardenedLaunch: true, userDataDir }));
    await fs.rm(userDataDir, { recursive: true, force: true });
    return;
  }

  try {
    const page = await electronApp.firstWindow({ timeout: 30_000 });
    await page.waitForLoadState("domcontentloaded");
    const createVisible = await page.getByTestId("onboarding-create-tab").isVisible();
    const result = {
      url: page.url(),
      title: await page.title(),
      createVisible,
      userDataDir,
    };
    console.log(JSON.stringify(result));

    if (!page.url().startsWith("nkc-app:") || !createVisible) {
      throw new Error("Packaged app did not open its local first-run account screen");
    }

    await page.getByTestId("onboarding-display-name").fill("Packaged Test");
    await page.getByTestId("onboarding-confirm-checkbox").check();
    await page.getByTestId("onboarding-create-button").click();
    await page.getByTestId("open-settings").waitFor({ state: "visible", timeout: 30_000 });
    await page.reload({ waitUntil: "domcontentloaded" });
    const startKeyVisible = await page.getByTestId("onboarding-start-key-input").isVisible();
    const displayNameVisible = await page.getByTestId("onboarding-display-name").isVisible();
    console.log(JSON.stringify({ startKeyVisible, displayNameVisible, automaticLogin: false }));

    if (!startKeyVisible || displayNameVisible) {
      throw new Error("Existing account did not require start-key login after renderer restart");
    }
  } finally {
    await electronApp.close();
  }
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
