#!/bin/sh

DIR=$(dirname $(readlink -f $0))

set -e

if [ "$1" = "build" ]; then
    podman build -t ctf-thereott/backend -f Dockerfile.build $DIR
fi

podman run --name ctf-thereott_backend ctf-thereott/backend
mkdir -p $DIR/bin
podman cp ctf-thereott_backend:/tmp/thereott $DIR/bin/thereott
podman rm ctf-thereott_backend
strip $DIR/bin/thereott

echo "Done!"