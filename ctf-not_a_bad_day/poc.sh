#!/bin/bash

set -e

DIR=$(dirname "$(realpath "$0")")

mkdir -p /tmp/mount

nbdfuse /tmp/mount --tcp localhost 1234 &
nbdfuse_pid=$!

while ! mountpoint -q /tmp/mount; do sleep 1; done

IMAGE_FILE="/tmp/mount/nbd"
OUTPUT_DIR="/tmp/elfs"

rm -rf "$OUTPUT_DIR.1"

echo "Recovering ELF files from $IMAGE_FILE to $OUTPUT_DIR"

photorec /d "$OUTPUT_DIR" /cmd "$IMAGE_FILE" partition_none,options,mode_ext2,fileopt,everything,disable,elf,enable,search > /dev/null 2>&1

OUTPUT_DIR="$OUTPUT_DIR.1"

for elf_file in $OUTPUT_DIR/*.elf; do chmod +x "$elf_file" && "$elf_file" | awk -F ": " '{print $1, $2}'; done | sort -n | awk '{print $2}' | tr -d '\n'
echo

rm -rf "$OUTPUT_DIR"

fusermount -u /tmp/mount

kill $nbdfuse_pid 2>/dev/null || true

rm -rf /tmp/mount
