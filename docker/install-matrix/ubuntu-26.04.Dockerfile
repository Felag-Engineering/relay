# Install-matrix image for Ubuntu 26.04 LTS: the official base image plus systemd, booted as
# PID 1 (CMD /usr/sbin/init) so the packages are installed against a running service manager.
# Built and run only by scripts/install-matrix-host.sh in CI. It is a test fixture and is
# never published or shipped. The base is pinned by its multi-arch index digest.
FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

ENV container=docker DEBIAN_FRONTEND=noninteractive

# The packages declare no external dependencies; the apt lists stay because the matrix's
# dependency-refusal check needs a working apt.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus curl ca-certificates jq procps hostname passwd \
        util-linux findutils diffutils

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
