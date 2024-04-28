# Prequel

Medium difficulty pwn challenge. Part One.

> Bob, Alice and Eve are huge fans of greetings. They collect so many of them that they need something more than a simple text file to store them. Previously they used JSON databases, because JSON is great for that, right? But a recent power outage caused a corruption of their database. It didn't end up writing the closing `}`. Now they came up with a new idea. And so was born `prequel`. Fancy a greeting? Come, and get one!
>
> The port is 3117.

## How to run

The image was tested with podman, but should work fine with docker as well.

0. Clone the repo and cd to the root folder of the particular challenge
1. Build the image: `podman build -t ctf-prequel:latest .`
2. Run the image: `podman rm -f ctf-prequel:latest; podman run --name ctf-prequel -it --rm -p 3117:3117 -e CHALLENGE_PORT=3117 ctf-prequel:latest`

Connect on port 3117.

<details>
<summary>Writeup (Spoiler)</summary>

If we check the binary with `checksec`, we see:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   5849 Symbols      No    0               0               ./out/prequel
```

The binary is not PIE, so we can easily find gadgets. The binary is also not fully RELRO, so we can overwrite the GOT. NX and stack canary are a pity though, but it may not even be a problem.

Time for some static analysis in IDA Free (or your favorite decompiler of choice). We see the following `main` function:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[64]; // [rsp+0h] [rbp-40h] BYREF

  ignore_me_init_signal(argc, argv, envp);
  init_buffering();
  disable_exec_syscall();
  print_version();
  read_name(v4);
  puts("Fetching your message...");
  get_message("SELECT message FROM messages WHERE name=?;", v4);
  seccomp_release(ctx);
  return 0;
}
```

Gladly the binary isn't stripped, so we see a bunch of meaningful function names. They disable some syscalls with seccomp, which isn't a good sign:

```c
__int64 disable_exec_syscall()
{
  int v0; // r8d
  int v1; // r9d
  int v2; // r8d
  int v3; // r9d

  ctx = seccomp_init(2147418112LL);
  seccomp_rule_add(ctx, 0, 59, 0, v0, v1);
  seccomp_rule_add(ctx, 0, 322, 0, v2, v3);
  return seccomp_load(ctx);
}
```

We can see that the `execve` and `execveat` syscalls are disabled. This is a common technique to prevent shellcode execution. But we can still use ROP to get the flag. It also kinda hints that way.

`read_name` on the other hand contains a sky-clear buffer overflow:

```c
__int64 __fastcall read_name(__int64 a1)
{
  puts("Enter your name: ");
  return gets(a1);
}
```

We can overwrite the return address and execute arbitrary code. The stack is executable, so we can just ROP our way to the flag. But its unclear where that is actually. We got a `messages_debug.db` file, so we shall examine that:

```sh
[steve@todo ctf-prequel]$ sqlite3 assets/messages_debug.db 
SQLite version 3.45.2 2024-03-12 11:06:23
Enter ".help" for usage hints.
sqlite> .tables
flag      messages
sqlite> .schema flag
CREATE TABLE flag (flag TEXT);
sqlite> SELECT * FROM flag;
HCSC24{this_is
_a_fake_
flag}
sqlite>
```

The flag seems to be in the database and there is even a function that's not called anywhere, but it is contained anyway:

```c
__int64 __fastcall print_debug_flag(unsigned int a1)
{
  int v1; // eax
  int v2; // r8d
  int v3; // r9d
  int v4; // eax
  int v5; // r8d
  int v6; // r9d
  int v7; // eax
  int v8; // r8d
  int v9; // r9d
  __int64 v10; // rax
  __int64 v12; // [rsp+10h] [rbp-20h] BYREF
  __int64 v13; // [rsp+18h] [rbp-18h] BYREF
  int v14; // [rsp+24h] [rbp-Ch]
  const char *v15; // [rsp+28h] [rbp-8h]

  v15 = "SELECT flag FROM flag LIMIT ?;";
  puts("Fetching debug flags...");
  v14 = sqlite3_open("messages_debug.db", &v13);
  if ( v14 )
  {
    v1 = sqlite3_errmsg(v13);
    fprintf(
      (_DWORD)stderr,
      (unsigned int)"Cannot open database: %s\n",
      v1,
      (unsigned int)"Cannot open database: %s\n",
      v2,
      v3);
    sqlite3_close(v13);
  }
  puts("Opened database successfully");
  v14 = sqlite3_prepare_v2(v13, v15, 0xFFFFFFFFLL, &v12, 0LL);
  if ( v14 )
  {
    v4 = sqlite3_errmsg(v13);
    fprintf(
      (_DWORD)stderr,
      (unsigned int)"Failed to prepare statement: %s\n",
      v4,
      (unsigned int)"Failed to prepare statement: %s\n",
      v5,
      v6);
    sqlite3_close(v13);
  }
  v14 = sqlite3_bind_int(v12, 1LL, a1);
  if ( v14 )
  {
    v7 = sqlite3_errmsg(v13);
    fprintf(
      (_DWORD)stderr,
      (unsigned int)"Failed to bind int: %s\n",
      v7,
      (unsigned int)"Failed to bind int: %s\n",
      v8,
      v9);
    sqlite3_close(v13);
  }
  puts("Prepared statement successfully");
  while ( 1 )
  {
    v14 = sqlite3_step(v12);
    if ( v14 != 100 )
      break;
    v10 = sqlite3_column_text(v12, 0LL);
    puts(v10);
  }
  sqlite3_finalize(v12);
  return sqlite3_close(v13);
}
```

`ret2win` to this is useless though, as it reads from `message_debug.db` and not `messages.db`.

`get_message` is interesting though:

```c
__int64 __fastcall get_message(__int64 a1, __int64 a2)
{
  int v2; // eax
  int v3; // r8d
  int v4; // r9d
  int v5; // eax
  int v6; // r8d
  int v7; // r9d
  unsigned int v8; // eax
  int v9; // eax
  int v10; // r8d
  int v11; // r9d
  __int64 v12; // rax
  __int64 v14; // [rsp+18h] [rbp-18h] BYREF
  __int64 v15; // [rsp+20h] [rbp-10h] BYREF
  int v16; // [rsp+2Ch] [rbp-4h]

  v16 = sqlite3_open("messages.db", &v15);
  if ( v16 )
  {
    v2 = sqlite3_errmsg(v15);
    fprintf(
      (_DWORD)stderr,
      (unsigned int)"Cannot open database: %s\n",
      v2,
      (unsigned int)"Cannot open database: %s\n",
      v3,
      v4);
    sqlite3_close(v15);
  }
  v16 = sqlite3_prepare_v2(v15, a1, 0xFFFFFFFFLL, &v14, 0LL);
  if ( v16 )
  {
    v5 = sqlite3_errmsg(v15);
    fprintf(
      (_DWORD)stderr,
      (unsigned int)"Failed to prepare statement: %s\n",
      v5,
      (unsigned int)"Failed to prepare statement: %s\n",
      v6,
      v7);
    sqlite3_close(v15);
  }
  v8 = j_strlen_ifunc(a2);
  v16 = sqlite3_bind_text(v14, 1LL, a2, v8, 0LL);
  if ( v16 )
  {
    v9 = sqlite3_errmsg(v15);
    fprintf(
      (_DWORD)stderr,
      (unsigned int)"Failed to bind text: %s\n",
      v9,
      (unsigned int)"Failed to bind text: %s\n",
      v10,
      v11);
    sqlite3_close(v15);
  }
  while ( 1 )
  {
    v16 = sqlite3_step(v14);
    if ( v16 != 100 )
      break;
    v12 = sqlite3_column_text(v14, 0LL);
    puts(v12);
  }
  sqlite3_finalize(v14);
  return sqlite3_close(v15);
}
```

It's quite unusual that one passes the SQL query as a parameter. We can use that to our advantage at which point this just becomes a simple `ret2win` challenge with additional string arguments involved.

We just need to find the right string. Thankfully a `SELECT flag FROM flag LIMIT ?;` query is already there in `print_debug_flag`. We just need the arg that is later passed to `sqlite3_bind_text`. So a number as a string. It's cool that we get a handy version string:

```
.rodata:00000000005A1048 unk_5A1048      db  31h ; 1             ; DATA XREF: .data:version↓o
.rodata:00000000005A1049                 db  30h ; 0
.rodata:00000000005A104A                 db  31h ; 1
```

`101`, but who cares, that satisfies our need. All that's left is to find the right gadgets and craft the exploit. Thankfully it can even be pulled off before the canary check, so we don't even need to leak the canary.

For my reference exploit, see [poc.py](poc.py).

Note: You can solve this challenge by calling `read` too, but that's not what I would like to see if I give you such a sweet hand-baked string to use there. :P

</details>