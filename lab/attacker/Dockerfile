# =============================================================================
# INF2005 ACW3 - Kali attacker box (assessment workstation)
# -----------------------------------------------------------------------------
# Based on the official Kali rolling image. Only a focused tool set is installed
# so the image stays small and boots quickly for the demo, instead of pulling
# the full kali-linux-everything metapackage. Add more with apt as needed.
#
# A VM-based Kali install is an equally valid alternative (see
# docs/01-environment-architecture.md); this container just makes the attacker
# reproducible inside docker-compose and attached to the same lab network.
# =============================================================================
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        # HTTP / general
        curl wget ca-certificates net-tools iproute2 iputils-ping dnsutils \
        # WebDAV client tooling (scenario 1 reconnaissance)
        cadaver davtest \
        # scripting + request crafting used across scenarios
        python3 python3-pip python3-requests \
        # web assessment helpers
        nikto nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
# Keep the container alive so the team can `docker compose exec attacker bash`.
CMD ["sleep", "infinity"]
