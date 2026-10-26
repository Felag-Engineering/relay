# Install-matrix image for Debian 13: the official base image plus systemd, booted as PID 1
# (CMD /usr/sbin/init) so the packages are installed against a running service manager. The
# no-systemd row runs this same image with `sleep infinity` in place of init. Built and run
# only by scripts/install-matrix-host.sh in CI. It is a test fixture and is never published
# or shipped. The base is pinned by its multi-arch index digest.
FROM debian:13@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308

ENV container=docker DEBIAN_FRONTEND=noninteractive

# The packages declare no external dependencies; the apt lists stay because the matrix's
# dependency-refusal check needs a working apt.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus curl ca-certificates jq procps hostname passwd \
        util-linux findutils diffutils

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
