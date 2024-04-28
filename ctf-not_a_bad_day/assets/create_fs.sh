#!/bin/bash

set -e

DIR=$(dirname "$(realpath "$0")")

podman build -t ctf-not_a_bad_day/fs_builder -f Dockerfile.build "$DIR"

rm -f "$DIR/fs.img"

fallocate -l 50M "$DIR/fs.img"

LOOP_DEV=$(sudo losetup --find --show "$DIR/fs.img")

sudo mkfs.ext4 -L notabadday "$LOOP_DEV"

mkdir -p "$DIR/mountpoint"
sudo mount "$LOOP_DEV" "$DIR/mountpoint"

sudo mkdir -p "$DIR/mountpoint/files"

FLAG="HCSC24{nbd_1s_4_SiCK_SyS4dm1n_t00l_f0r_r3m0t3_0s_1n57all4t10n}"
IMAGES_DIR="$DIR/images"
IMAGE_FILES=("$IMAGES_DIR"/*)

ELF_DIR=$(mktemp -d)
echo "Using ELF directory: $ELF_DIR"

for ((i = 0; i < ${#FLAG}; i++)); do
    CURRENT_CHAR="${FLAG:$i:1}"

    cat > "$ELF_DIR/$i.c" <<EOF
#include <stdio.h>

int main() {
    puts("$i: $CURRENT_CHAR");
    return 0;
}
EOF
done

podman run --rm -v "$ELF_DIR:/code" --name fs_builder ctf-not_a_bad_day/fs_builder /bin/sh -c "cd /code && for i in *.c; do gcc -o \${i%.c} \$i; done"

for ((i = 0; i < ${#FLAG}; i++)); do
    sudo cp "${IMAGE_FILES[$i]}" "$DIR/mountpoint/files/"
    sudo cp "$ELF_DIR/$i" "$DIR/mountpoint/files/"
done

sync

for ((i = 0; i < ${#FLAG}; i++)); do
    sudo rm -f "$DIR/mountpoint/files/$i"
done

if [[ ${#IMAGE_FILES[@]} -gt ${#FLAG} ]]; then
    for ((i = ${#FLAG}; i < ${#IMAGE_FILES[@]}; i++)); do
        sudo cp "${IMAGE_FILES[$i]}" "$DIR/mountpoint/files/"
    done
fi

rm -rf "$ELF_DIR"

sudo umount "$DIR/mountpoint"

sudo losetup --detach "$LOOP_DEV"

rm -rf "$DIR/mountpoint"

echo "Done."
