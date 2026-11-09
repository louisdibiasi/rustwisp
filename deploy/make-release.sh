#!/usr/bin/env bash
# Build a release tarball for this machine: both binaries, the example config and the hardened
# systemd files, plus a sha256 checksum. Output lands in dist/.
#
#   deploy/make-release.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

version="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
arch="$(uname -m)"
name="rustwisp-${version}-linux-${arch}"
stage="dist/${name}"

cargo build --release --locked -p rustwisp -p rustwisp-client

rm -rf "$stage"
mkdir -p "$stage/systemd"
cp target/release/rustwisp target/release/rustwisp-cli "$stage/"
cp deploy/rustwisp.conf "$stage/rustwisp.conf"
cp deploy/systemd/rustwisp.service deploy/systemd/rustwisp.sysusers deploy/systemd/rustwisp.tmpfiles "$stage/systemd/"
cp LICENSE "$stage/"
[ -f README.md ] && cp README.md "$stage/"
[ -f docs/GUIDE.md ] && cp docs/GUIDE.md "$stage/"

tar -C dist -czf "dist/${name}.tar.gz" "$name"
(cd dist && sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256")
rm -rf "$stage"
echo "built dist/${name}.tar.gz"
cat "dist/${name}.tar.gz.sha256"
