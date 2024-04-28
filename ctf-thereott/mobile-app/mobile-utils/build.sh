#!/bin/sh

DIR=$(dirname $(readlink -f $0))

set -e

if [ "$1" = "build" ]; then
    podman build -t ctf-thereott/utils:latest -f Dockerfile.build $DIR
fi

NDK_PATH=$(podman run --rm ctf-thereott/utils /bin/ash -c 'echo /opt/sdk/ndk/*')

podman run --name ctf-thereott_utils -e CC=$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang -e CGO_ENABLED=1 -e GOOS=android -e GOARCH=arm64 -e GOARM=7 -v $DIR:/build:z ctf-thereott/utils /bin/ash -c 'cd /build && /usr/bin/go build -o /tmp/libutils.so -buildmode=c-shared -ldflags="-s -w" /build'
mkdir -p $DIR/libs/arm64-v8a
podman cp ctf-thereott_utils:/tmp/libutils.so $DIR/libs/arm64-v8a/libutils.so
podman rm ctf-thereott_utils
podman run --name ctf-thereott_utils -e CC=$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi26-clang -e CGO_ENABLED=1 -e GOOS=android -e GOARCH=arm -e GOARM=7 -v $DIR:/build:z ctf-thereott/utils /bin/ash -c 'cd /build && /usr/bin/go build -o /tmp/libutils.so -buildmode=c-shared -ldflags="-s -w" /build'
mkdir -p $DIR/libs/armeabi-v7a
podman cp ctf-thereott_utils:/tmp/libutils.so $DIR/libs/armeabi-v7a/libutils.so
podman rm ctf-thereott_utils
podman run --name ctf-thereott_utils -e CC=$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android26-clang -e CGO_ENABLED=1 -e GOOS=android -e GOARCH=amd64 -v $DIR:/build:z ctf-thereott/utils /bin/ash -c 'cd /build && /usr/bin/go build -o /tmp/libutils.so -buildmode=c-shared -ldflags="-s -w" /build'
mkdir -p $DIR/libs/x86_64
podman cp ctf-thereott_utils:/tmp/libutils.so $DIR/libs/x86_64/libutils.so
podman rm ctf-thereott_utils

echo "Done!"