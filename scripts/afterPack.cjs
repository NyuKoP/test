const path = require("node:path");
const {
  FuseVersion,
  FuseV1Options,
  flipFuses,
} = require("@electron/fuses");

exports.default = async function afterPack(context) {
  const executableName =
    context.electronPlatformName === "darwin"
      ? context.packager.appInfo.productFilename
      : context.packager.appInfo.productFilename +
        (context.electronPlatformName === "win32" ? ".exe" : "");
  const executablePath =
    context.electronPlatformName === "darwin"
      ? path.join(
          context.appOutDir,
          `${context.packager.appInfo.productFilename}.app`,
          "Contents",
          "MacOS",
          executableName
        )
      : path.join(context.appOutDir, executableName);

  await flipFuses(executablePath, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
  });
};
