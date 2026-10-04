# syntax=docker/dockerfile:1

# Image for the getmac command-line tool. Build it with packaging/build-docker.sh
# ("pdm run build-docker"), which also sets the label build arguments, or from the
# repository root with:
#   docker build --pull -f packaging/Dockerfile -t getmac .
# See the "Docker" section of CONTRIBUTING.md for the build arguments, and the
# "Docker" section of README.md for usage.
# packaging/Dockerfile.dockerignore limits which files are sent to the build.
# Published images are built by .github/workflows/docker.yml, which also sets the
# description, source, and licenses labels as annotations. Keep them the same.

# The base image can be changed with --build-arg BASE_IMAGE=<image>, for example
# docker.io/library/python:3.13-slim-trixie. It must be Debian-based, since
# iproute2 is installed with apt.

# BASE_IMAGE Debian-based Python image to build on (iproute2 is installed with apt)
ARG BASE_IMAGE=docker.io/library/python:3.14-slim-trixie

FROM ${BASE_IMAGE}

# getmac reads /proc and /sys for IPv4, interface, and default interface lookups.
# IPv6 lookups need the "ip" command from iproute2, since Linux has no /proc
# file for the IPv6 neighbor table.
# This step also applies Debian security updates that are newer than the base
# image. DEBIAN_FRONTEND is set per command instead of with ENV, so it isn't kept
# in the image's runtime environment.
# hadolint ignore=DL3008
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install from a bind mount of the source, so the source isn't kept in the image.
# The mount is writable (writes are discarded) since pdm-backend deletes any
# leftover .pdm-build directory in the source.
# The pip settings are exported so they cover both pip commands and pip's build
# subprocess: no download cache, no root user warning, and no .pyc files for pip
# or the standard library (getmac's own modules are still compiled).
# pip is removed after the install, since getmac doesn't need it at runtime and
# the libraries vendored in pip otherwise show up in vulnerability scans.
# Last, importing the CLI compiles the standard library modules getmac uses on
# purpose. The base image has no standard library .pyc files, and the
# unprivileged runtime user can't write them, so otherwise every run would
# recompile them.
RUN --mount=type=bind,target=/src,rw \
    export PIP_NO_CACHE_DIR=1 PIP_ROOT_USER_ACTION=ignore PYTHONDONTWRITEBYTECODE=1 \
    && python -m pip install /src \
    && python -m pip uninstall -y pip \
    && unset PYTHONDONTWRITEBYTECODE \
    && python -c "import getmac.__main__"

# Image metadata, using the OCI annotation keys:
# https://specs.opencontainers.org/image-spec/annotations/
# Version, revision, and created are set with --build-arg and are empty otherwise.
# The ARGs are declared after the RUN steps so new values don't invalidate the build cache.
# The base.name and base.digest keys aren't set, since the base image is a tag
# whose digest changes when it's updated and isn't known here.

# VERSION getmac version, for the org.opencontainers.image.version label
ARG VERSION
# REVISION Git commit the image is built from, for the org.opencontainers.image.revision label
ARG REVISION
# CREATED Build time in RFC 3339 format, for the org.opencontainers.image.created label
ARG CREATED
LABEL org.opencontainers.image.title="getmac" \
      org.opencontainers.image.description="Platform-independent pure-Python module to get a MAC address" \
      org.opencontainers.image.authors="Christopher Goes <ghostofgoes@gmail.com>" \
      org.opencontainers.image.url="https://github.com/GhostofGoes/getmac" \
      org.opencontainers.image.source="https://github.com/GhostofGoes/getmac" \
      org.opencontainers.image.documentation="https://ghostofgoes.github.io/getmac/" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# Run as an unprivileged user (nobody). None of getmac's lookups in this image need root.
USER 65534:65534

ENTRYPOINT ["getmac"]
