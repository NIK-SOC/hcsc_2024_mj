#!/bin/sh

DIR=$(dirname $(readlink -f $0))

set -e

if [ "$1" = "build" ]; then
    podman build -t ctf-thereott/native:latest -f Dockerfile.build $DIR
fi

podman run --name ctf-thereott_native -e NDK_PROJECT_PATH=/build -v $DIR:/build:z ctf-thereott/native /bin/ash -c '/opt/sdk/ndk/*/ndk-build'
podman rm ctf-thereott_native

echo "Done!"