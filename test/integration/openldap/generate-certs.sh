#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CERT_DIR="$SCRIPT_DIR/certs"

mkdir -p "$CERT_DIR"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -days 3650 \
  -nodes \
  -keyout "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -subj "/CN=Authrim Wordwarden Test CA"

openssl req \
  -newkey rsa:2048 \
  -nodes \
  -keyout "$CERT_DIR/ldap.key" \
  -out "$CERT_DIR/ldap.csr" \
  -subj "/CN=localhost"

printf '%s\n' \
  "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  "extendedKeyUsage=serverAuth" \
  "keyUsage=digitalSignature,keyEncipherment" \
  > "$CERT_DIR/ldap.ext"

openssl x509 \
  -req \
  -in "$CERT_DIR/ldap.csr" \
  -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/ldap.crt" \
  -days 3650 \
  -sha256 \
  -extfile "$CERT_DIR/ldap.ext"

# The osixia/openldap fixture copies the mounted key into a runtime directory
# owned by the openldap user. Keep the generated test key host-readable so the
# container can copy it during bootstrap. These keys are local fixture material.
chmod 0644 "$CERT_DIR/ldap.key"
