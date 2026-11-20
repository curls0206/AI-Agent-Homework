# vulnrepair Agent image.
# The Agent runs inside this container and starts its own Podman engine (nested) to run the
# build / regression / PoC sandbox, so the whole run is reproducible on any platform that can
# run a privileged Podman container.
#
#   podman build --network=host -t vulnrepair-agent -f Containerfile .
#   podman run --rm --privileged --network=host vulnrepair-agent demo
# Multi-platform index digest of quay.io/podman/stable v5.8.9 (amd64, arm64, ppc64le, s390x).
FROM quay.io/podman/stable@sha256:55d98815a34b8f796d9bc3130e7ea5eb070ec388c64124d12e876d07df8b7834

LABEL org.opencontainers.image.title="vulnrepair agent" \
      org.opencontainers.image.description="Generate-and-verify vulnerability repair agent with a nested Podman sandbox"

USER root
# Python 3.13 is the version the project is tested with (3.14 changes asyncio internals).
RUN dnf install -y --setopt=install_weak_deps=False python3.13 git-core \
    && ln -sf /usr/bin/python3.13 /usr/local/bin/python3 \
    && dnf clean all

# The base image disables cgroups for nested containers; the sandbox needs them to enforce
# its pids / memory / cpu limits.
RUN mkdir -p /etc/containers/containers.conf.d \
    && printf '[containers]\ncgroups="enabled"\ncgroupns="private"\n' \
       > /etc/containers/containers.conf.d/99-vulnrepair.conf

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY src ./src
COPY sandbox ./sandbox
COPY tests ./tests
COPY scripts ./scripts
COPY container/entrypoint.sh /usr/local/bin/vulnrepair-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/vulnrepair-entrypoint \
    && chmod +x /usr/local/bin/vulnrepair-entrypoint

ENV PYTHONPATH=/app/src \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/root

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/vulnrepair-entrypoint"]
CMD ["demo"]
