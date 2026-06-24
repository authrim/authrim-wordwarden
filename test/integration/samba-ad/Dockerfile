FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends samba krb5-user ldap-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/samba-ad-entrypoint
RUN chmod +x /usr/local/bin/samba-ad-entrypoint

EXPOSE 389 636 88 464 53 135 139 445

ENTRYPOINT ["/usr/local/bin/samba-ad-entrypoint"]
