#!/usr/bin/env bash
# verify-profile.sh — issue a throwaway leaf via the Vault PKI c2pa-leaf
# role and assert the strict KU/EKU/BasicConstraints profile. Fails
# non-zero on drift so this can be wired into CI.
#
# Requires:
#   VAULT_ADDR, VAULT_TOKEN  in env
#   openssl, jq              on PATH
#   curl                     on PATH
#
# Optional:
#   VAULT_CACERT             path to CA bundle for self-signed Vault TLS
#   MOUNT                    PKI mount path (default: pki-c2pa)
#   ROLE                     role name (default: c2pa-leaf)

set -euo pipefail

MOUNT="${MOUNT:-pki-c2pa}"
ROLE="${ROLE:-c2pa-leaf}"

if [[ -z "${VAULT_ADDR:-}" || -z "${VAULT_TOKEN:-}" ]]; then
  echo "FATAL: VAULT_ADDR and VAULT_TOKEN must be set" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. Generate a throwaway P-256 keypair + CSR.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/leaf.key.pem" 2>/dev/null
openssl req -new -key "$WORK/leaf.key.pem" \
  -subj "/CN=cuecrux daemon C2PA signer (verify-profile)" \
  -out "$WORK/leaf.csr.pem" 2>/dev/null

# 2. POST the CSR to Vault, signed by the c2pa-leaf role.
CURL_OPTS=(--silent --show-error --fail)
if [[ -n "${VAULT_CACERT:-}" ]]; then
  CURL_OPTS+=(--cacert "$VAULT_CACERT")
fi

REQ_BODY="$(jq -n \
  --arg csr "$(cat "$WORK/leaf.csr.pem")" \
  '{csr: $csr, common_name: "cuecrux daemon C2PA signer", ttl: "1h"}')"

curl "${CURL_OPTS[@]}" \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  -d "$REQ_BODY" \
  "$VAULT_ADDR/v1/$MOUNT/sign/$ROLE" \
  | jq -r .data.certificate > "$WORK/leaf.cert.pem"

if [[ ! -s "$WORK/leaf.cert.pem" ]]; then
  echo "FATAL: Vault returned empty certificate" >&2
  exit 3
fi

# 3. Decode the leaf and assert the strict profile.
TEXT="$(openssl x509 -in "$WORK/leaf.cert.pem" -noout -text)"

# KU = Digital Signature only.
if ! echo "$TEXT" | grep -A1 'X509v3 Key Usage' | grep -E 'Digital Signature$' > /dev/null; then
  echo "FAIL: leaf KU is not exactly 'Digital Signature'" >&2
  echo "$TEXT" | grep -A1 'X509v3 Key Usage' >&2
  exit 4
fi
if echo "$TEXT" | grep -A1 'X509v3 Key Usage' | grep -E 'Certificate Sign|CRL Sign|Key Encipherment|Key Agreement' > /dev/null; then
  echo "FAIL: leaf KU includes extra bits beyond Digital Signature" >&2
  exit 5
fi

# EKU = E-mail Protection only.
if ! echo "$TEXT" | grep -A1 'X509v3 Extended Key Usage' | grep -E '^[ ]*E-mail Protection$' > /dev/null; then
  echo "FAIL: leaf EKU is not exactly 'E-mail Protection'" >&2
  echo "$TEXT" | grep -A1 'X509v3 Extended Key Usage' >&2
  exit 6
fi
if echo "$TEXT" | grep -A1 'X509v3 Extended Key Usage' | grep -E 'TLS Web|Code Signing|OCSP|Time Stamping' > /dev/null; then
  echo "FAIL: leaf EKU includes extra purposes" >&2
  exit 7
fi

# BasicConstraints CA:FALSE asserted (NOT absent — the constraint must be present).
if ! echo "$TEXT" | grep -A1 'X509v3 Basic Constraints' | grep -E 'CA:FALSE' > /dev/null; then
  echo "FAIL: leaf BasicConstraints is not 'CA:FALSE' (missing or CA:TRUE)" >&2
  echo "$TEXT" | grep -A1 'X509v3 Basic Constraints' >&2
  exit 8
fi

# Public key algorithm = P-256.
if ! echo "$TEXT" | grep -E 'Public Key Algorithm: id-ecPublicKey' > /dev/null; then
  echo "FAIL: leaf is not P-256 / id-ecPublicKey" >&2
  exit 9
fi
if ! echo "$TEXT" | grep -E 'ASN1 OID: prime256v1' > /dev/null; then
  echo "FAIL: leaf curve is not prime256v1 / secp256r1" >&2
  exit 10
fi

# Signature algorithm = ecdsa-with-SHA256.
if ! echo "$TEXT" | grep -E 'Signature Algorithm: ecdsa-with-SHA256' > /dev/null; then
  echo "FAIL: leaf signature alg is not ecdsa-with-SHA256" >&2
  exit 11
fi

echo "PROFILE OK: leaf has KU=DigitalSignature only, EKU=EmailProtection only,"
echo "            BasicConstraints CA:FALSE asserted, P-256 + ecdsa-with-SHA256."
