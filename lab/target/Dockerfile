# =============================================================================
# INF2005 ACW3 - Vulnerable Apache HTTP Server target
# -----------------------------------------------------------------------------
# Builds Apache httpd from source so the exact version is pinned and the three
# modules under assessment are guaranteed to be present:
#   - mod_dav / mod_dav_fs   (CVE-2026-93546)
#   - mod_auth_digest        (CVE-2026-73636)
#   - mod_proxy_html / mod_xml2enc (CVE-2026-63686)
#
# HTTPD_VERSION selects the build:
#   2.4.68  -> last VULNERABLE release  (default, used by the `target` service)
#   2.4.69  -> PATCHED release          (used by the `target-patched` service)
#
# Everything here runs locally on team hardware. This image is a deliberately
# vulnerable lab fixture; it must never be exposed outside the lab network.
# =============================================================================
FROM debian:bookworm-slim AS build

ARG HTTPD_VERSION=2.4.68
ARG APR_VERSION=1.7.5
ARG APR_UTIL_VERSION=1.6.3
ENV DEBIAN_FRONTEND=noninteractive

# Build toolchain + the dev libraries the assessed modules need.
#   libxml2-dev  -> required for mod_proxy_html and mod_xml2enc
#   libpcre2-dev -> required by httpd 2.4
#   libssl-dev   -> TLS (used when discussing the digest capture-replay defence)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential wget ca-certificates \
        libpcre2-dev libxml2-dev libssl-dev libnghttp2-dev libexpat1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# APR and APR-util are bundled into httpd's srclib so the build is fully
# self-contained and reproducible from the Apache archive.
RUN wget -q "https://archive.apache.org/dist/httpd/httpd-${HTTPD_VERSION}.tar.bz2" \
    && wget -q "https://archive.apache.org/dist/apr/apr-${APR_VERSION}.tar.bz2" \
    && wget -q "https://archive.apache.org/dist/apr/apr-util-${APR_UTIL_VERSION}.tar.bz2" \
    && tar xjf "httpd-${HTTPD_VERSION}.tar.bz2" \
    && tar xjf "apr-${APR_VERSION}.tar.bz2" \
    && tar xjf "apr-util-${APR_UTIL_VERSION}.tar.bz2" \
    && mv "apr-${APR_VERSION}" "httpd-${HTTPD_VERSION}/srclib/apr" \
    && mv "apr-util-${APR_UTIL_VERSION}" "httpd-${HTTPD_VERSION}/srclib/apr-util"

WORKDIR /usr/src/httpd-${HTTPD_VERSION}

# `most` gives the standard module set as shared (DSO) objects. The assessed
# modules are forced to `=shared` so their .so files exist and the LoadModule
# lines in the lab config resolve; MPMs are built shared so mpm_event loads as a
# module too. proxy_html + xml2enc build only because libxml2-dev is installed.
RUN ./configure \
        --prefix=/usr/local/apache2 \
        --enable-mods-shared=most \
        --enable-mpms-shared=all \
        --enable-dav=shared --enable-dav-fs=shared \
        --enable-auth-digest=shared \
        --enable-proxy=shared --enable-proxy-http=shared \
        --enable-proxy-html=shared --enable-xml2enc=shared \
        --with-included-apr \
        --with-pcre=/usr/bin/pcre2-config \
    && make -j"$(nproc)" \
    && make install

# -----------------------------------------------------------------------------
# Runtime image
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
ARG HTTPD_VERSION=2.4.68
ENV DEBIAN_FRONTEND=noninteractive HTTPD_VERSION=${HTTPD_VERSION}

# Runtime shared libraries only (no compilers in the running target).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-8-0 libxml2 libssl3 libnghttp2-14 libexpat1 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r www-data 2>/dev/null || true

COPY --from=build /usr/local/apache2 /usr/local/apache2

# Ensure the dynamic loader finds the bundled APR/APR-util shared libraries that
# the from-source build installs under the prefix (belt-and-suspenders to rpath).
ENV PATH="/usr/local/apache2/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/apache2/lib"
WORKDIR /usr/local/apache2

# Lab configuration (vulnerable by default; swap via LAB_CONF at run time).
COPY conf/lab-vuln.conf     /usr/local/apache2/conf/lab-vuln.conf
COPY conf/lab-hardened.conf /usr/local/apache2/conf/lab-hardened.conf
COPY entrypoint.sh          /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Which config the entrypoint loads: lab-vuln.conf (default) or lab-hardened.conf
ENV LAB_CONF=lab-vuln.conf

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["httpd", "-D", "FOREGROUND"]
