#!/bin/sh

DIR=$(dirname $(readlink -f $0))

set -e

if [ "$1" = "build" ]; then
    podman build -t ctf-patch_adams/src:latest -f Dockerfile.build $DIR
fi

podman run --name ctf-patch_adams_src ctf-patch_adams/src
mkdir -p $DIR/../out/
podman cp ctf-patch_adams_src:/src/adams $DIR/../out/adams
podman rm ctf-patch_adams_src

echo "Done!"