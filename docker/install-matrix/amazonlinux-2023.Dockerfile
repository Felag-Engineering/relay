# Install-matrix image for Amazon Linux 2023: the official base image plus systemd, booted as
# PID 1 (CMD /usr/sbin/init) so the packages are installed against a running service manager.
# Built and run only by scripts/install-matrix-host.sh in CI. It is a test fixture and is
# never published or shipped. The base is pinned by its multi-arch index digest.
FROM amazonlinux:2023@sha256:c04a1012acc483977f61f7f91c28624a39a621e56a59781319a75dec528be9b6

ENV container=docker

# No curl package: the base provides /usr/bin/curl through curl-minimal, which conflicts with
# it. The image edits no dnf or rpm configuration: the row installs under the distribution's
# default _pkgverify_level.
RUN dnf install -y systemd util-linux shadow-utils procps-ng hostname jq findutils diffutils \
    && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
