#!/usr/bin/env bash
set -euo pipefail

VERSION=""
BASE_URL="https://github.com/authrim/authrim-wordwarden/releases/download"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/authrim-wordwarden"
STATE_DIR="/var/lib/authrim-wordwarden"
SERVICE_PATH="/etc/systemd/system/authrim-wordwarden.service"
DRY_RUN=0
VERIFY_SIGNATURE=1
CERTIFICATE_IDENTITY_REGEXP="https://github.com/authrim/authrim-wordwarden/.github/workflows/release.yml@refs/tags/.*"
CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"

usage() {
  cat <<'USAGE'
Install Authrim Wordwarden on a Linux systemd host.

Usage:
  install.sh --version v0.1.0-beta.1 [options]

Options:
  --base-url URL          Release base URL. Default: GitHub releases.
  --install-dir PATH      Binary install directory. Default: /usr/local/bin
  --config-dir PATH       Config directory. Default: /etc/authrim-wordwarden
  --state-dir PATH        State directory. Default: /var/lib/authrim-wordwarden
  --service-path PATH     systemd unit path. Default: /etc/systemd/system/authrim-wordwarden.service
  --certificate-identity-regexp REGEXP
                          Cosign keyless certificate identity constraint.
  --certificate-oidc-issuer URL
                          Cosign keyless OIDC issuer constraint.
  --skip-signature        Verify checksum only. Not recommended for production.
  --dry-run               Print actions without writing files.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --config-dir)
      CONFIG_DIR="$2"
      shift 2
      ;;
    --state-dir)
      STATE_DIR="$2"
      shift 2
      ;;
    --service-path)
      SERVICE_PATH="$2"
      shift 2
      ;;
    --certificate-identity-regexp)
      CERTIFICATE_IDENTITY_REGEXP="$2"
      shift 2
      ;;
    --certificate-oidc-issuer)
      CERTIFICATE_OIDC_ISSUER="$2"
      shift 2
      ;;
    --skip-signature)
      VERIFY_SIGNATURE=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  echo "--version is required" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

OS="linux"
VERSION_NO_V="${VERSION#v}"
ARTIFACT="authrim-wordwarden_${VERSION_NO_V}_${OS}_${ARCH}.tar.gz"
RELEASE_URL="${BASE_URL}/${VERSION}"
ARTIFACT_URL="${RELEASE_URL}/${ARTIFACT}"
CHECKSUM_URL="${RELEASE_URL}/SHA256SUMS"
SIGNATURE_URL="${RELEASE_URL}/SHA256SUMS.sig"
BUNDLE_URL="${RELEASE_URL}/SHA256SUMS.bundle"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

run() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf 'dry-run: %q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

echo "version=${VERSION}"
echo "artifact_url=${ARTIFACT_URL}"
echo "checksum_url=${CHECKSUM_URL}"
echo "signature_url=${SIGNATURE_URL}"
echo "signature_identity_regexp=${CERTIFICATE_IDENTITY_REGEXP}"
echo "signature_oidc_issuer=${CERTIFICATE_OIDC_ISSUER}"
echo "install_dir=${INSTALL_DIR}"
echo "config_dir=${CONFIG_DIR}"
echo "state_dir=${STATE_DIR}"

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "dry-run complete"
  exit 0
fi

curl -fsSL "${ARTIFACT_URL}" -o "${TMP_DIR}/${ARTIFACT}"
curl -fsSL "${CHECKSUM_URL}" -o "${TMP_DIR}/SHA256SUMS"

(
  cd "${TMP_DIR}"
  grep " ${ARTIFACT}$" SHA256SUMS | sha256sum -c -
)

if [[ "${VERIFY_SIGNATURE}" == "1" ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is required for signature verification; rerun with --skip-signature only for controlled testing" >&2
    exit 1
  fi
  curl -fsSL "${SIGNATURE_URL}" -o "${TMP_DIR}/SHA256SUMS.sig"
  curl -fsSL "${BUNDLE_URL}" -o "${TMP_DIR}/SHA256SUMS.bundle"
  cosign verify-blob \
    --certificate-identity-regexp "${CERTIFICATE_IDENTITY_REGEXP}" \
    --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
    --signature "${TMP_DIR}/SHA256SUMS.sig" \
    --bundle "${TMP_DIR}/SHA256SUMS.bundle" \
    "${TMP_DIR}/SHA256SUMS"
fi

tar -C "${TMP_DIR}" -xzf "${TMP_DIR}/${ARTIFACT}"

run install -d -m 0755 "${INSTALL_DIR}"
run install -m 0755 "${TMP_DIR}/wordwarden" "${INSTALL_DIR}/wordwarden"
run install -d -m 0750 "${CONFIG_DIR}"
run install -d -m 0750 "${STATE_DIR}"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  run install -m 0644 "${TMP_DIR}/config.example.yaml" "${CONFIG_DIR}/config.yaml"
fi

unit_tmp="${TMP_DIR}/authrim-wordwarden.service"
cat > "${unit_tmp}" <<UNIT
[Unit]
Description=Authrim Wordwarden Directory Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/wordwarden --config ${CONFIG_DIR}/config.yaml serve
Restart=on-failure
RestartSec=5s
DynamicUser=yes
StateDirectory=authrim-wordwarden
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
UNIT

run install -m 0644 "${unit_tmp}" "${SERVICE_PATH}"
run systemctl daemon-reload

echo "installed wordwarden ${VERSION}"
echo "edit ${CONFIG_DIR}/config.yaml, then run: systemctl enable --now authrim-wordwarden"
