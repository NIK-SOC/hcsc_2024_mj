#!/bin/sh

DIR=$(dirname $(readlink -f $0))

set -e

if [ "$1" = "build" ]; then
    podman build -t ctf-return_of_jack/backend -f Dockerfile.build $DIR
fi

podman run --name ctf-return_of_jack_backend ctf-return_of_jack/backend
mkdir -p $DIR/bin
podman cp ctf-return_of_jack_backend:/tmp/returnofjack $DIR/bin/returnofjack
podman rm ctf-return_of_jack_backend
strip $DIR/bin/returnofjack

echo "Done!"