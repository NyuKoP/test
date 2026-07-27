import { describe, expect, it } from "vitest";
import { buildWindowsExpandArchiveArgs } from "../unpack";

describe("Windows archive extraction command", () => {
  it("passes paths as positional arguments instead of interpolating PowerShell source", () => {
    const archivePath = "C:\\tmp\\archive'; Write-Output PWNED; '.zip";
    const destination = "C:\\tmp\\dest'; Remove-Item victim; '";
    const args = buildWindowsExpandArchiveArgs(archivePath, destination);

    expect(args[3]).not.toContain(archivePath);
    expect(args[3]).not.toContain(destination);
    expect(args.at(-2)).toBe(archivePath);
    expect(args.at(-1)).toBe(destination);
  });
});
