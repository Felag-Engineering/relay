# Install-matrix image for Rocky Linux 10, standing for RHEL-compatible 10: the Rocky
# Enterprise Software Foundation's own image, rockylinux/rockylinux (Docker's library image
# ends at 9), plus systemd, booted as PID 1 (CMD /usr/sbin/init) so the packages are
# installed against a running service manager. Built and run only by
# scripts/install-matrix-host.sh in CI. It is a test fixture and is never published or
# shipped. The base is pinned by its multi-arch index digest.
FROM rockylinux/rockylinux:10@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834

ENV container=docker

# crypto-policies-scripts provides update-crypto-policies, which the FIPS repeat needs. The
# image edits no dnf or rpm configuration: the row installs under the distribution's default
# _pkgverify_level.
RUN dnf install -y systemd util-linux shadow-utils procps-ng hostname jq findutils diffutils \
        crypto-policies-scripts \
    && (command -v curl >/dev/null || dnf install -y curl) \
    && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
