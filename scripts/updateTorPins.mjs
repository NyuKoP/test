import fs from "node:fs/promises";
import path from "node:path";

const TOR_RELEASE_BASE = "https://dist.torproject.org/torbrowser";
const PIN_FILE = path.join(process.cwd(), "src", "main", "onion", "pinnedHashes.ts");

const readTextOverride = async (environmentName) => {
  const filePath = process.env[environmentName];
  return filePath ? fs.readFile(filePath, "utf8") : null;
};

const fetchText = async (url) => {
  const response = await fetch(url, {
    headers: { "User-Agent": "nkc-tor-pin-updater" },
  });
  if (!response.ok) throw new Error(`Fetch failed ${response.status} ${url}`);
  return response.text();
};

const compareVersions = (a, b) => {
  const aParts = a.split(".").map(Number);
  const bParts = b.split(".").map(Number);
  for (let index = 0; index < Math.max(aParts.length, bParts.length); index += 1) {
    const difference = (aParts[index] ?? 0) - (bParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
};

const platformMap = new Map([
  ["android", "android"],
  ["linux", "linux"],
  ["macos", "darwin"],
  ["windows", "win32"],
]);

const archMap = new Map([
  ["aarch64", "arm64"],
  ["armv7", "arm"],
  ["i686", "ia32"],
  ["x86", "ia32"],
  ["x86_64", "x64"],
]);

const renderPin = ({ platform, arch, version, filename, sha256 }) =>
  `    [makePinnedKey({ platform: "${platform}", arch: "${arch}", version: "${version}", filename: "${filename}" })]: "${sha256}",`;

const main = async () => {
  const index =
    (await readTextOverride("NKC_TOR_INDEX_FILE")) ??
    (await fetchText(`${TOR_RELEASE_BASE}/`));
  const versions = Array.from(index.matchAll(/href="(\d+\.\d+\.\d+)\//g), (match) => match[1]);
  const latest = versions.sort(compareVersions).at(-1);
  if (!latest) throw new Error("No Tor Browser release found");

  const manifest =
    (await readTextOverride("NKC_TOR_MANIFEST_FILE")) ??
    (await fetchText(`${TOR_RELEASE_BASE}/${latest}/sha256sums-signed-build.txt`));
  const pins = [];
  for (const line of manifest.split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64})\s+(tor-expert-bundle-(android|linux|macos|windows)-(aarch64|armv7|i686|x86|x86_64)-(\d+\.\d+\.\d+)\.tar\.gz)$/i);
    if (!match) continue;
    const [, sha256, filename, platformName, archName, version] = match;
    pins.push({
      platform: platformMap.get(platformName),
      arch: archMap.get(archName),
      version,
      filename,
      sha256: sha256.toLowerCase(),
    });
  }
  if (pins.length === 0) throw new Error(`No Tor expert bundle hashes found for ${latest}`);

  let source = await fs.readFile(PIN_FILE, "utf8");
  const additions = pins.filter(({ version, filename }) =>
    !source.includes(`version: "${version}", filename: "${filename}"`)
  );
  if (additions.length === 0) {
    console.log(`Tor ${latest}: all ${pins.length} pins are already present`);
    return;
  }

  const marker = "  },\n} as const;";
  if (!source.includes(marker)) throw new Error(`Could not locate Tor pin map in ${PIN_FILE}`);
  source = source.replace(marker, `${additions.map(renderPin).join("\n")}\n${marker}`);
  await fs.writeFile(PIN_FILE, source, "utf8");
  console.log(`Tor ${latest}: added ${additions.length} pin(s) to ${PIN_FILE}`);
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
