#!/bin/bash

set -e

DIR=$(dirname "$(realpath "$0")")

IMAGE_FILE="$DIR/fs.img"
OUTPUT_DIR="/tmp/elfs"

rm -rf "$OUTPUT_DIR.1"

echo "Recovering ELF files from $IMAGE_FILE to $OUTPUT_DIR"

photorec /d "$OUTPUT_DIR" /cmd "$IMAGE_FILE" partition_none,options,mode_ext2,fileopt,everything,disable,elf,enable,search > /dev/null 2>&1

OUTPUT_DIR="$OUTPUT_DIR.1"

for elf_file in $OUTPUT_DIR/*.elf; do chmod +x "$elf_file" && "$elf_file" | awk -F ": " '{print $1, $2}'; done | sort -n | awk '{print $2}' | tr -d '\n'
echo

rm -rf "$OUTPUT_DIR"
