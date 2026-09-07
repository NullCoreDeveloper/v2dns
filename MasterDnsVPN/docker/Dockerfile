FROM debian:bookworm-slim

ARG TARGETARCH
ARG TARGETVARIANT

LABEL org.opencontainers.image.source=https://github.com/NullCoreDeveloper/MasterDnsVPN

ENV DEBIAN_FRONTEND=noninteractive \
  APP_DIR=/opt/masterdnsvpn \
  DATA_DIR=/data \
  CONFIG_FILE=server_config.toml \
  KEY_FILE=encrypt_key.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
  bash \
  ca-certificates \
  tini \
  unzip \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /opt/masterdnsvpn /data

COPY release_assets/ /tmp/release_assets/
COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN set -eux; \
  case "${TARGETARCH}" in \
  amd64) \
  PREFIX="MasterDnsVPN_Server_Linux_AMD64" ;; \
  arm64) \
  PREFIX="MasterDnsVPN_Server_Linux_ARM64" ;; \
  arm) \
  case "${TARGETVARIANT}" in \
  v5) PREFIX="MasterDnsVPN_Server_Linux_ARMV5" ;; \
  v7|"") PREFIX="MasterDnsVPN_Server_Linux_ARMV7" ;; \
  *) echo "Unsupported ARM variant: ${TARGETVARIANT}" >&2; exit 1 ;; \
  esac ;; \
  mips64le) \
  PREFIX="MasterDnsVPN_Server_Linux_MIPS64LE" ;; \
  *) \
  echo "Unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
  esac; \
  ZIP_PATH="$(find /tmp/release_assets -type f -name "${PREFIX}.zip" | head -n1)"; \
  if [ -z "${ZIP_PATH}" ]; then \
    ZIP_PATH="$(find /tmp/release_assets -type f -name "${PREFIX}_v*.zip" | head -n1)"; \
  fi; \
  if [ -z "${ZIP_PATH}" ]; then \
    echo "Could not find ZIP for ${PREFIX}" >&2; exit 1; \
  fi; \
  unzip -q "${ZIP_PATH}" -d /tmp/extracted; \
  BIN="$(find /tmp/extracted -type f -name "${PREFIX}_v*" | sort -V | tail -n1)"; \
  if [ -z "${BIN}" ]; then echo "Could not find extracted binary for ${PREFIX}" >&2; exit 1; fi; \
  mv "${BIN}" /opt/masterdnsvpn/masterdnsvpn; \
  chmod 0755 /opt/masterdnsvpn/masterdnsvpn /usr/local/bin/docker-entrypoint.sh; \
  rm -rf /tmp/release_assets /tmp/extracted

WORKDIR /opt/masterdnsvpn

EXPOSE 53/tcp 53/udp
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["-nowait"]
