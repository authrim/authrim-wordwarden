#!/usr/bin/env bash
set -euo pipefail

REALM="${SAMBA_REALM:-EXAMPLE.TEST}"
DOMAIN="${SAMBA_DOMAIN:-EXAMPLE}"
ADMIN_PASSWORD="${SAMBA_ADMIN_PASSWORD:-Passw0rd!}"
ALICE_PASSWORD="${SAMBA_ALICE_PASSWORD:-Password123!}"
HOST_IP="${SAMBA_HOST_IP:-127.0.0.1}"
DNS_FORWARDER="${SAMBA_DNS_FORWARDER:-1.1.1.1}"

mkdir -p /var/lib/samba/private /var/cache/samba /run/samba

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision     --use-rfc2307     --realm="${REALM}"     --domain="${DOMAIN}"     --server-role=dc     --dns-backend=SAMBA_INTERNAL     --adminpass="${ADMIN_PASSWORD}"     --host-ip="${HOST_IP}"

  cat >> /etc/samba/smb.conf <<EOF

[global]
        ldap server require strong auth = no
        dns forwarder = ${DNS_FORWARDER}
EOF

  samba-tool user create alice "${ALICE_PASSWORD}"     --given-name=Alice     --surname=Example     --mail-address=alice@example.test     --must-change-at-next-login=no
  samba-tool group add staff || true
  samba-tool group addmembers staff alice || true
fi

exec samba -i -M single
