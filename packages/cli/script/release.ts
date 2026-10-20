#!/usr/bin/env bun
// Creates the GitHub release with one tarball per platform and their SHA256SUMS
// (used by the install script). The Homebrew formula and the AUR package are
// published from that release by script/distribute.ts, in a separate CI job
// that holds their deploy keys. Skipped when GH_TOKEN is missing.

import { $ } from "bun"
import { fileURLToPath } from "url"
import pkg from "../package.json"

const dir = fileURLToPath(new URL("..", import.meta.url))
process.chdir(dir)

const version = pkg.version
const tag = `v${version}`
const repo = "anomalyco/opentunnel"
const platforms = ["linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64"]
const sha: Record<string, string> = {}
for (const platform of platforms) {
  const tarball = `./dist/opentunnel-${platform}.tar.gz`
  await $`chmod 755 ./dist/cli-${platform}/bin/opentunnel`
  await $`tar -czf ${tarball} -C ./dist/cli-${platform}/bin opentunnel`
  sha[platform] = new Bun.CryptoHasher("sha256").update(await Bun.file(tarball).arrayBuffer()).digest("hex")
}
await Bun.write(
  "./dist/SHA256SUMS",
  platforms.map((platform) => `${sha[platform]}  opentunnel-${platform}.tar.gz\n`).join(""),
)

// GitHub release
if (process.env.GH_TOKEN) {
  if ((await $`gh release view ${tag} --repo ${repo}`.nothrow().quiet()).exitCode === 0) {
    console.log(`release ${tag} already exists`)
  } else {
    const assets = [...platforms.map((platform) => `./dist/opentunnel-${platform}.tar.gz`), "./dist/SHA256SUMS"]
    await $`gh release create ${tag} ${assets} --repo ${repo} --title ${tag} --generate-notes`
  }
} else {
  console.warn("GH_TOKEN is not set; skipping the GitHub release")
}
