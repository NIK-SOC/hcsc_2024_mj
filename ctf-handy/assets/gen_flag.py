from pwn import *

r = remote("localhost", 1337)

r.sendlineafter(b"encrypt: ", b"HCSC24{a_german_word_for_mobile_phone}")
r.recvuntil(b"go: ")
encrypted_flag = r.recvline().strip()
print(encrypted_flag.decode())
