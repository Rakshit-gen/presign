#!/bin/sh
# presign installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Rakshit-gen/presign/main/scripts/install.sh | sh
#
# Downloads the release binary for your OS and architecture, checks its
# SHA256 against the release's checksums.txt, and installs it into
# $HOME/.local/bin.
#
# Environment overrides:
#   PRESIGN_VERSION   version to install (default: latest)
#   PRESIGN_BIN_DIR   install directory (default: $HOME/.local/bin)

set -eu

REPO="Rakshit-gen/presign"
VERSION="${PRESIGN_VERSION:-latest}"
BIN_DIR="${PRESIGN_BIN_DIR:-$HOME/.local/bin}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
	fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q "$1" -O "$2"; }
	fetch_stdout() { wget -qO- "$1"; }
else
	die "need curl or wget"
fi

case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "unsupported OS $(uname -s); presign ships for macOS and Linux" ;;
esac
case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
esac

if [ "$VERSION" = latest ]; then
	VERSION="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" |
		sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
	[ -n "$VERSION" ] || die "could not find the latest release; set PRESIGN_VERSION"
fi
case "$VERSION" in v*) tag="$VERSION" ;; *) tag="v$VERSION" ;; esac

archive="presign_${tag#v}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${tag}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/presign.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

info "downloading ${archive}"
fetch "${base}/${archive}" "${tmp}/${archive}" || die "download failed: ${base}/${archive}"
fetch "${base}/checksums.txt" "${tmp}/checksums.txt" || die "could not download checksums.txt"

expected="$(grep " ${archive}\$" "${tmp}/checksums.txt" | awk '{print $1}')"
[ -n "$expected" ] || die "no checksum listed for ${archive}"
if command -v sha256sum >/dev/null 2>&1; then
	actual="$(sha256sum "${tmp}/${archive}" | awk '{print $1}')"
else
	actual="$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for ${archive}"

tar -xzf "${tmp}/${archive}" -C "$tmp"
mkdir -p "$BIN_DIR"
mv "${tmp}/presign" "${BIN_DIR}/presign"
chmod +x "${BIN_DIR}/presign"
info "installed presign ${tag} to ${BIN_DIR}/presign"

case ":${PATH}:" in
	*":${BIN_DIR}:"*) ;;
	*) info "${BIN_DIR} is not on your PATH; add it to your shell profile" ;;
esac
