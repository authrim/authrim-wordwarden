#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-}"
OUT_DIR="${OUT_DIR:-dist/release}"
PACKAGE_PREFIX="${PACKAGE_PREFIX:-authrim-wordwarden}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64}"

if [[ -z "${VERSION}" ]]; then
  VERSION="$(go run ./cmd/wordwarden version)"
fi
ARTIFACT_VERSION="${VERSION#v}"

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}/${PACKAGE_PREFIX}_"*.tar.gz
rm -f "${OUT_DIR}/SHA256SUMS" "${OUT_DIR}/SHA256SUMS.sig" "${OUT_DIR}/SHA256SUMS.bundle"
rm -f "${OUT_DIR}/${PACKAGE_PREFIX}_${ARTIFACT_VERSION}_sbom.json"

for target in ${TARGETS}; do
  goos="${target%/*}"
  goarch="${target#*/}"
  work_dir="$(mktemp -d)"
  binary="${work_dir}/wordwarden"
  artifact="${PACKAGE_PREFIX}_${ARTIFACT_VERSION}_${goos}_${goarch}.tar.gz"

  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w -X github.com/authrim/authrim-wordwarden/internal/app.version=${ARTIFACT_VERSION}" \
      -o "${binary}" ./cmd/wordwarden

  cp README.md LICENSE config.example.yaml "${work_dir}/"
  tar -C "${work_dir}" -czf "${OUT_DIR}/${artifact}" wordwarden README.md LICENSE config.example.yaml
  rm -rf "${work_dir}"
done

(
  cd "${OUT_DIR}"
  sha256sum ./*.tar.gz > SHA256SUMS
)

go list -m -json all > "${OUT_DIR}/${PACKAGE_PREFIX}_${ARTIFACT_VERSION}_sbom.json"

if command -v cosign >/dev/null 2>&1; then
  cosign sign-blob --yes \
    --output-signature "${OUT_DIR}/SHA256SUMS.sig" \
    --bundle "${OUT_DIR}/SHA256SUMS.bundle" \
    "${OUT_DIR}/SHA256SUMS"
elif [[ "${WORDWARDEN_ALLOW_UNSIGNED_RELEASE:-}" == "1" ]]; then
  echo "warning: cosign not found; leaving release unsigned because WORDWARDEN_ALLOW_UNSIGNED_RELEASE=1" >&2
else
  echo "error: cosign is required to sign release checksums" >&2
  exit 1
fi

echo "release artifacts written to ${OUT_DIR}"
