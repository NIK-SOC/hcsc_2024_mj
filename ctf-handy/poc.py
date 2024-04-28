from pwn import *
from string import ascii_lowercase

r = remote("localhost", 1337)

r.sendlineafter(b"encrypt: ", "/".join(ascii_lowercase).encode())
r.recvuntil(b"go: ")
lookup_table = r.recvline().strip()

lookup_table = dict(zip(lookup_table.decode().split("/"), ascii_lowercase))

encrypted_flag = "440222077770222024{20_4033077706020660_906660777030_333066607770_60666022044405550330_704406660660330}"
flag = ""

i = 0
while i < len(encrypted_flag):
    if encrypted_flag[i].isdigit():
        encrypted_char = encrypted_flag[i]
        i += 1
        while (
            i < len(encrypted_flag)
            and encrypted_flag[i].isdigit()
            and encrypted_flag[i] != "0"
        ):
            encrypted_char += encrypted_flag[i]
            i += 1
        if i < len(encrypted_flag) and encrypted_flag[i] == "0":
            encrypted_char += encrypted_flag[i]
            flag += lookup_table[encrypted_char]
            i += 1
        else:
            flag += encrypted_char
    else:
        flag += encrypted_flag[i]
        i += 1

print("Decrypted flag:", flag)
