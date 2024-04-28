#!/bin/sh

DIR=$(dirname $(readlink -f $0))

set -e

if [ "$1" = "build" ]; then
    podman build -t ctf-thereott/mobileapp:latest -f Dockerfile.build $DIR
fi

podman run -it --name ctf-thereott_mobileapp -v $DIR/assets:/assets:z ctf-thereott/mobileapp /bin/ash -c '/build/gradlew assembleRelease && zipalign -v -p 4 /build/app/build/outputs/apk/release/app-release-unsigned.apk /build/app/build/outputs/apk/release/app-release-unsigned-aligned.apk && apksigner sign --ks /assets/hcsc2024.jks --out /build/app/build/outputs/apk/release/app-release.apk /build/app/build/outputs/apk/release/app-release-unsigned-aligned.apk'
mkdir -p $DIR/out
podman cp ctf-thereott_mobileapp:/build/app/build/outputs/apk/release/app-release.apk $DIR/out/app-release.apk
podman rm ctf-thereott_mobileapp

echo "Done!"