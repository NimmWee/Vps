#!/usr/bin/env bash
# Runtime downloads are pinned and checksum verified. Does not change SSH auth.
set -euo pipefail
umask 077
VERSION="1.0.0"
BUNDLE_SHA256="30ea1801f9c98e11d41e1408796fe2bf0dd803debc10882c19815c7e9ab2d063"
BASE="https://raw.githubusercontent.com/NimmWee/Vps/v${VERSION}"
KIT_SHA256="e5ab4d53a6dce3e0d6aa5fe6ac9e43c1d13408e8556091a7940980f1352ef5c2"
WITH_KIT=0
QR=0
ARGS=()
for ARG in "$@"; do
  case "$ARG" in
    --with-kit) WITH_KIT=1 ;;
    --qr) QR=1; ARGS+=("$ARG") ;;
    --help|-h)
      cat <<'HELP'
Usage: bash install.sh [--with-kit] [--qr] [options]
  Default: lightweight FreeTurn + kernel WireGuard + SSH Fail2ban.
  --with-kit       Also run pinned upstream 3X-UI KIT if absent (interactive).
  --endpoint HOST  Public IPv4 or DNS name; default: detect current IPv4.
  --vk-link-file P Read your private VK call URL from a file; otherwise prompt.
  --adopt-legacy   Adopt the recognized kit-freeturn layout, preserving keys.
  --instance NAME --port 56001 --backend-port 51830 --subnet 10.77.43.0/24
  restore FILE    Install from an encrypted vps-vk backup on a fresh VPS.
Profiles are written root-only; use `vps-vk profiles --show` to print them.
HELP
      exit 0 ;;
    *) ARGS+=("$ARG") ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run this installer as root.' >&2; exit 1; }
[[ -f /etc/os-release && -d /run/systemd/system ]] || { echo 'A systemd Linux VPS is required.' >&2; exit 1; }
# Read distribution values, not arbitrary shell instructions from external files.
OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
OS_VERSION=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
case "$OS_ID:$OS_VERSION" in
  ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
  *) echo 'Supported: Ubuntu 22.04/24.04 or Debian 12/13.' >&2; exit 1 ;;
esac
ARCH=$(dpkg --print-architecture)
[[ "$ARCH" == amd64 || "$ARCH" == arm64 ]] || { echo 'Supported architectures: amd64, arm64.' >&2; exit 1; }
TMP=$(mktemp -d /var/tmp/vps-vk-install.XXXXXXXX)
trap 'rm -rf -- "$TMP"' EXIT
fetch() { curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --retry 3 "$1" -o "$2"; }
# --bundle-dir is for local review/testing; normal one-command use downloads the pinned bundle.
BUNDLE_DIR=${VPS_VK_BUNDLE_DIR:-}
if [[ -z "$BUNDLE_DIR" ]]; then
  fetch "$BASE/dist/vps-vk-v${VERSION}.tar.gz" "$TMP/bundle.tar.gz"
  printf '%s  %s\n' "$BUNDLE_SHA256" "$TMP/bundle.tar.gz" | sha256sum --check --status || { echo 'Bundle checksum mismatch.' >&2; exit 1; }
  mkdir "$TMP/bundle"
  tar --extract --gzip --file "$TMP/bundle.tar.gz" --directory "$TMP/bundle" --no-same-owner --no-same-permissions
  BUNDLE_DIR="$TMP/bundle"
fi
if [[ $WITH_KIT -eq 1 ]]; then
  if [[ -x /usr/local/bin/kit ]]; then
    echo 'Existing KIT detected; its installer and CLI will not be run.'
  else
    fetch 'https://raw.githubusercontent.com/itsnotkubrick/3X-UI_KIT/v1.2.1/scripts/3x-ui.sh' "$TMP/kit.sh"
    printf '%s  %s\n' "$KIT_SHA256" "$TMP/kit.sh" | sha256sum --check --status || { echo 'KIT checksum mismatch.' >&2; exit 1; }
    bash "$TMP/kit.sh" </dev/tty
  fi
fi
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
apt-get -o DPkg::Lock::Timeout=60 update
PACKAGES=(ca-certificates python3 wireguard-tools iptables nftables fail2ban python3-systemd openssl)
[[ $QR -eq 0 ]] || PACKAGES+=(qrencode)
apt-get -o DPkg::Lock::Timeout=60 --no-install-recommends install -y "${PACKAGES[@]}"
COMMAND=install
if [[ ${#ARGS[@]} -gt 0 && ${ARGS[0]} == restore ]]; then COMMAND=restore; ARGS=("${ARGS[@]:1}"); fi
python3 "$BUNDLE_DIR/src/vps_vk.py" "$COMMAND" "${ARGS[@]}" --bundle "$BUNDLE_DIR"
echo
echo 'Ready. Phone profiles: vps-vk profiles --show'
echo 'Health check: vps-vk status'
echo 'Encrypted migration backup: vps-vk backup /root/vpn.vkbackup'
