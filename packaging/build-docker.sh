#!/usr/bin/env bash
# Build the getmac Docker image from packaging/Dockerfile, with the version,
# git commit, and build time labels filled in. It can be run from any directory.
#
# Usage: packaging/build-docker.sh [docker build options]
#    or: pdm run build-docker [docker build options]
#
# The image is tagged "getmac" and "getmac:<version>". Set IMAGE to use another
# name (e.g. IMAGE=getmac-dev), or a name with a tag to only use that tag
# (e.g. IMAGE=getmac:dev). Any arguments are passed to "docker build", for example
# --no-cache, --pull=false, or --build-arg BASE_IMAGE=<image>.
set -euo pipefail

# cd's output is discarded, since it prints the directory if CDPATH is set
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." > /dev/null && pwd)"

if ! command -v docker > /dev/null; then
    echo "error: docker isn't installed or isn't on the PATH (https://docs.docker.com/get-docker/)" >&2
    exit 1
fi

version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$repo_root/getmac/getmac.py")"
if [[ -z "$version" ]]; then
    echo "error: couldn't find __version__ in $repo_root/getmac/getmac.py" >&2
    exit 1
fi

# The git commit, with "-dirty" added if the files that go into the image have
# uncommitted changes. It's empty if the repository root isn't the top of a git
# checkout with commits (e.g. an extracted source archive), or git isn't installed.
revision=""
if prefix="$(git -C "$repo_root" rev-parse --show-prefix 2> /dev/null)" && [[ -z "$prefix" ]]; then
    revision="$(git -C "$repo_root" rev-parse --verify --quiet HEAD || true)"
    image_files=(getmac LICENSE pyproject.toml README.md packaging/Dockerfile packaging/Dockerfile.dockerignore)
    if [[ -n "$revision" && -n "$(git -C "$repo_root" --no-optional-locks status --porcelain -- "${image_files[@]}")" ]]; then
        revision="$revision-dirty"
    fi
fi
created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

image="${IMAGE:-getmac}"
tags=("$image")
if [[ "${image##*/}" != *:* ]]; then
    tags+=("$image:$version")
fi

cmd=(docker build --pull -f "$repo_root/packaging/Dockerfile")
cmd+=(--build-arg "VERSION=$version" --build-arg "REVISION=$revision" --build-arg "CREATED=$created")
for tag in "${tags[@]}"; do
    cmd+=(-t "$tag")
done
cmd+=("$@" "$repo_root")

echo "Building getmac $version image: ${tags[*]}"
printf '+'
printf ' %q' "${cmd[@]}"
printf '\n'
"${cmd[@]}"
