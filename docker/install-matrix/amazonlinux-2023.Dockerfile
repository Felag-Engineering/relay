# Install-matrix image for Amazon Linux 2023: the official base image plus systemd, booted as
# PID 1 (CMD /usr/sbin/init) so the packages are installed against a running service manager.
# Built and run only by scripts/install-matrix-host.sh in CI. It is a test fixture and is
# never published or shipped. The base is pinned by its multi-arch index digest.
FROM amazonlinux:2023.0.20230614.0@sha256:28004508959f548dd98278f746c577a41b8340dc295e51d309e721e4e217bb85

ENV container=docker

# No curl package: the base provides /usr/bin/curl through curl-minimal, which conflicts with
# it. The image edits no dnf or rpm configuration: the row installs under the distribution's
# default _pkgverify_level.
RUN dnf install -y systemd util-linux shadow-utils procps-ng hostname jq findutils diffutils \
    && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
