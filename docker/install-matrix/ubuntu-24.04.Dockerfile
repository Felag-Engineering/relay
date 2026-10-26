# Install-matrix image for Ubuntu 24.04 LTS: the official base image plus systemd, booted as
# PID 1 (CMD /usr/sbin/init) so the packages are installed against a running service manager.
# Built and run only by scripts/install-matrix-host.sh in CI. It is a test fixture and is
# never published or shipped. The base is pinned by its multi-arch index digest.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

ENV container=docker DEBIAN_FRONTEND=noninteractive

# The packages declare no external dependencies; the apt lists stay because the matrix's
# dependency-refusal check needs a working apt.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus curl ca-certificates jq procps hostname passwd \
        util-linux findutils diffutils

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
