FROM envoyproxy/envoy:distroless-v1.38.8 AS envoy
FROM debian:trixie-slim

# Use the Linux stand's archived browser builds so repeat captures use the
# same ClientHellos. Supply them as the "archives" build context.
RUN --mount=type=bind,from=archives,target=/archives \
    apt-get update --error-on=any \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        /archives/chrome.deb /archives/edge.deb \
        ca-certificates curl firefox-esr haproxy iproute2 libnss3-tools \
        nginx openssl passt python3 tcpdump tshark util-linux xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV STAND_WORK=/stand
WORKDIR /opt/realitystand
COPY . .

RUN --mount=type=bind,from=archives,target=/archives \
    mkdir -p /stand/bin /stand/root /stand/runs /stand/www /opt/firefox-156.0.1 /opt/firefox-160.0 \
    && ln -s /opt /stand/root/opt \
    && tar -xJf /archives/firefox-156.0.1.tar.xz -C /opt/firefox-156.0.1 --strip-components=1 \
    && tar -xJf /archives/firefox-160.0.tar.xz -C /opt/firefox-160.0 --strip-components=1 \
    && cd /archives \
    && grep ' caddy_2.11.9_linux_amd64.tar.gz$' caddy_2.11.9_checksums.txt | sha512sum -c - \
    && tar -xzf caddy_2.11.9_linux_amd64.tar.gz -C /stand/bin caddy \
    && sh /opt/realitystand/certs.sh /stand/certs/real \
    && printf '<html><body>stand</body></html>\n' > /stand/www/index.html \
    && head -c 5000000 /dev/urandom > /stand/www/blob5m \
    && head -c 1000000 /dev/urandom > /stand/www/blob1m

RUN curl -fsSL https://angie.software/keys/angie-signing.gpg.asc -o /tmp/angie-signing.asc \
    && printf '%s\n' 'deb [signed-by=/tmp/angie-signing.asc] https://download.angie.software/angie/debian/13 trixie main' > /tmp/angie.list \
    && apt-get -o Dir::Etc::sourcelist=/tmp/angie.list -o Dir::Etc::sourceparts=- update --error-on=any \
    && cd /tmp \
    && apt-get -o Dir::Etc::sourcelist=/tmp/angie.list -o Dir::Etc::sourceparts=- download angie \
    && dpkg-deb -x angie_*.deb angie-package \
    && install -m 755 angie-package/usr/sbin/angie /stand/bin/angie \
    && rm -rf /tmp/angie-package /tmp/angie_*.deb /tmp/angie.list /tmp/angie-signing.asc /var/lib/apt/lists/*

COPY --from=envoy /usr/local/bin/envoy /stand/bin/envoy

ENTRYPOINT ["python3", "/opt/realitystand/stand.py"]
