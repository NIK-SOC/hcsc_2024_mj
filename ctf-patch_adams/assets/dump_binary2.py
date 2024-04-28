import requests
import os
from json import loads

url = "http://localhost:8080"

reconstructed_elf_path = "/tmp/reconstructed_elf"
next_address = 0x0

if os.path.exists(reconstructed_elf_path):
    os.remove(reconstructed_elf_path)

data = {"command1": "o", "argument1": "", "command2": "h", "argument2": ""}
response = requests.post(url, data=data).text
size_index = response.find("0x")
size_hex = response[size_index : size_index + 10]
file_size = int(size_hex, 16)
print("File size:", hex(file_size))

while next_address + 16 <= file_size:
    data = {
        "command1": "s",
        "argument1": hex(next_address),
        "command2": "pxj",
        "argument2": "",
    }
    response = requests.post(url, data=data).text

    lines = response.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("["):
            break
    line = loads(line)

    with open(reconstructed_elf_path, "ab") as elf_file:
        binary_data = bytearray(line)
        elf_file.write(binary_data)

    next_address += len(binary_data)

if os.path.getsize(reconstructed_elf_path) != file_size:
    print("Error: Reconstructed ELF size doesn't match expected size.")

print("Reconstructed ELF created successfully at", reconstructed_elf_path)
