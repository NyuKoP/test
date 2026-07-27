const path = require("node:path");
const {
  FuseVersion,
  FuseV1Options,
  flipFuses,
} = require("@electron/fuses");

const resolveElectronExecutablePath = (context) => {
  const productFilename = context.packager.appInfo.productFilename;
  if (context.electronPlatformName === "darwin") {
    return path.join(
      context.appOutDir,
      `${productFilename}.app`,
      "Contents",
      "MacOS",
      productFilename
    );
  }
  if (context.electronPlatformName === "linux") {
    return path.join(context.appOutDir, context.packager.executableName);
  }
  return path.join(context.appOutDir, `${productFilename}.exe`);
};

exports.resolveElectronExecutablePath = resolveElectronExecutablePath;

exports.default = async function afterPack(context) {
  const executablePath = resolveElectronExecutablePath(context);

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
