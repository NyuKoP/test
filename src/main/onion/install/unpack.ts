import { execFile } from "node:child_process";

export const buildWindowsExpandArchiveArgs = (archivePath: string, destDir: string) => [
  "-NoProfile",
  "-NonInteractive",
  "-Command",
  "& { param($archive, $destination) Expand-Archive -Force -LiteralPath $archive -DestinationPath $destination }",
  archivePath,
  destDir,
];

export const unpackArchive = async (archivePath: string, destDir: string) => {
  const lowerPath = archivePath.toLowerCase();
  const run = async (cmd: string, args: string[]) => {
    return new Promise<void>((resolve, reject) => {
      execFile(cmd, args, { windowsHide: true }, (error, stdout, stderr) => {
        if (!error) {
          resolve();
          return;
        }
        const wrapped = new Error(
          `${error.message}\ncmd=${cmd} ${args.join(" ")}\n${stderr || stdout || ""}`.trim()
        );
        (wrapped as { details?: Record<string, unknown> }).details = {
          cmd,
          args,
          stderr: stderr?.toString?.() ?? String(stderr ?? ""),
          stdout: stdout?.toString?.() ?? String(stdout ?? ""),
          code: (error as unknown as { code?: string }).code,
        };
        reject(wrapped);
      });
    });
  };

  if (lowerPath.endsWith(".zip")) {
    if (process.platform === "win32") {
      await run("powershell", buildWindowsExpandArchiveArgs(archivePath, destDir));
      return;
    }
    await run("unzip", ["-o", archivePath, "-d", destDir]);
    return;
  }
  if (
    lowerPath.endsWith(".tar.gz") ||
    lowerPath.endsWith(".tgz") ||
    lowerPath.endsWith(".tar.xz")
  ) {
    await run(process.platform === "win32" ? "tar.exe" : "tar", [
      "-xf",
      archivePath,
      "-C",
      destDir,
    ]);
    return;
  }
  throw new Error("Unsupported archive format");
};
