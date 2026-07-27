import path from "node:path";
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const { resolveElectronExecutablePath } = require("../afterPack.cjs");

const createContext = (electronPlatformName) => ({
  appOutDir: path.join("release", `${electronPlatformName}-unpacked`),
  electronPlatformName,
  packager: {
    appInfo: { productFilename: "NKC" },
    executableName: "test",
  },
});

describe("afterPack executable resolution", () => {
  it("uses the Linux packager executable name", () => {
    expect(resolveElectronExecutablePath(createContext("linux"))).toBe(
      path.join("release", "linux-unpacked", "test")
    );
  });

  it("uses the product executable on Windows", () => {
    expect(resolveElectronExecutablePath(createContext("win32"))).toBe(
      path.join("release", "win32-unpacked", "NKC.exe")
    );
  });

  it("uses the executable inside the macOS application bundle", () => {
    expect(resolveElectronExecutablePath(createContext("darwin"))).toBe(
      path.join(
        "release",
        "darwin-unpacked",
        "NKC.app",
        "Contents",
        "MacOS",
        "NKC"
      )
    );
  });
});
