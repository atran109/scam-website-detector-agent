# Egress proxy: the crawler's only way out (DESIGN §5.6). Pinned base and package.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

RUN apk add --no-cache squid=6.12-r0 \
    && mkdir -p /var/log/squid \
    && chown squid:squid /var/log/squid

COPY squid.conf /etc/squid/squid.conf

# Run as the unprivileged squid user from the start (no root → setuid step, so cap_drop ALL works).
USER squid
EXPOSE 3128
CMD ["squid", "-N", "-d", "1", "-f", "/etc/squid/squid.conf"]
