# Not a Bad Day

A medium difficulty forensic challenge for better days.

> One day I woke up with a strange headache. What happened last night...? I don't remember. I woke up and the flag was gone from my computer. Can you help me? Let me at least have a better day today.
>
> Port is 1234.

## How to run

The image was tested with podman, but should work fine with docker as well.

0. Clone the repo and cd to the root folder of the particular challenge
1. Build the image: `podman build -t ctf-not_a_bad_day:latest .`
2. Run the image: `podman rm -f ctf-not_a_bad_day:latest; podman run --name ctf-not_a_bad_day -it --rm -p 1234:1234 ctf-not_a_bad_day:latest`

Connect on port 1234.

<details>
<summary>Writeup (Spoiler)</summary>

First let's see what we are dealing with:

```
[steve@todo ctf-not_a_bad_day]$ nmap -sV -p 1234-1234 127.0.0.1
Starting Nmap 7.94 ( https://nmap.org ) at 2024-03-28 22:41 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00020s latency).

PORT     STATE SERVICE VERSION
1234/tcp open  nbd     Network Block Device (new handshake)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
[steve@todo ctf-not_a_bad_day]$ nc localhost 1234
NBDMAGICIHAVEOPT
^C
```

Cool, so the name was indeed hinting at [Network Block Device](https://en.wikipedia.org/wiki/Network_block_device), an ancient protocol for sharing block devices over the network. Let's see if we can mount it. I will use `nbdfuse` as it doesn't require root privileges:

```
[steve@todo ctf-not_a_bad_day]$ mkdir /tmp/mount
[steve@todo ctf-not_a_bad_day]$ nbdfuse /tmp/mount --tcp localhost 1234
```

It did something. From a different terminal:

```
[steve@todo ctf-not_a_bad_day]$ ls -la /tmp/mount/nbd 
-rw-rw-rw- 1 steve steve 52428800 Mar 28 22:44 /tmp/mount/nbd
```

```
[steve@todo ctf-not_a_bad_day]$ echo "test" > /tmp/mount/nbd
bash: echo: write error: Operation not permitted
[steve@todo ctf-not_a_bad_day]$ rm /tmp/mount/nbd
rm: cannot remove '/tmp/mount/nbd': Function not implemented
```

It seems to be read only, so we can only rely on its content. We don't have to overwrite stuff. Let's see what's inside:

```
[steve@todo ctf-not_a_bad_day]$ file /tmp/mount/nbd
/tmp/mount/nbd: Linux rev 1.0 ext4 filesystem data, UUID=9519ff71-c7ed-48d3-bb74-26a13f434929, volume name "notabadday" (extents) (64bit) (large files) (huge files)
```

Sweet. For some reason I cannot mount it directly from a fuse mount. I assume that's just some fuse/nbdfuse limitation:

```
[steve@todo ctf-not_a_bad_day]$ sudo mount /tmp/mount/nbd /mnt/
[sudo] password for steve: 
mount: /mnt: fsconfig system call failed: /tmp/mount/nbd: Can't lookup blockdev.
       dmesg(1) may have more information after failed mount system call.
```

But it's a raw image, so we can copy it first and then try again:

```
[steve@todo ctf-not_a_bad_day]$ cp /tmp/mount/nbd /tmp/test.img
[steve@todo ctf-not_a_bad_day]$ sudo mount /tmp/test.img /mnt
[steve@todo ctf-not_a_bad_day]$ ls /mnt/
files  lost+found
```

It worked. Time to look around:

```
[steve@todo ctf-not_a_bad_day]$ ls -a /mnt/
.  ..  files  lost+found
[steve@todo ctf-not_a_bad_day]$ ls -a /mnt/files/
.    102.jpg  203.jpg  208.jpg  303.jpg  400.jpg  405.jpg  410.jpg 415.jpg  421.jpg  426.jpg  450.jpg  500.jpg  506.jpg  511.jpg  530.jpg
..   103.jpg  204.jpg  226.jpg  304.jpg  401.jpg  406.jpg  411.jpg 416.jpg  422.jpg  428.jpg  451.jpg  501.jpg  507.jpg  521.jpg  599.jpg
0.jpg  200.jpg  205.jpg  300.jpg  305.jpg  402.jpg  407.jpg  412.jpg 417.jpg  423.jpg  429.jpg  497.jpg  502.jpg  508.jpg  522.jpg
100.jpg  201.jpg  206.jpg  301.jpg  307.jpg  403.jpg  408.jpg  413.jpg  418.jpg  424.jpg  431.jpg  498.jpg  503.jpg  509.jpg  523.jpg
101.jpg  202.jpg  207.jpg  302.jpg  308.jpg  404.jpg  409.jpg  414.jpg  420.jpg  425.jpg  444.jpg  499.jpg  504.jpg  510.jpg  525.jpg
[steve@todo ctf-not_a_bad_day]$ sudo ls -a /mnt/lost+found/
.  ..
```

Nothing of interest... Just cat pictures. Maybe the files got deleted? It's `photorec` time! For those unaware, [Photorec](https://en.wikipedia.org/wiki/PhotoRec) is a great tool for recovering files from a disk image.

I will unmount the image first:

```
sudo umount /mnt
```

Then run `photorec` on the image. It needs a folder where it can recover files, so let us create one:

```
mkdir /tmp/files
photorec /tmp/test.img
```

We see a GUI:

```
Select a media and choose 'Proceed' using arrow keys:
>Disk /tmp/test.img - 52 MB / 50 MiB (RO)
```

I will select the disk and press `Enter`.

```
Disk /tmp/test.img - 52 MB / 50 MiB (RO)

     Partition                  Start        End    Size in sectors
      Unknown                  0   0  1     6  95 25     102400 [Whole disk]
>   P ext4                     0   0  1     6  95 25     102400 [notabadday]
```

Almost like a strange role-playing game. I will select the partition and press `Enter`.

```
To recover lost files, PhotoRec needs to know the filesystem type where the
file were stored:
>[ ext2/ext3 ] ext2/ext3/ext4 filesystem
 [ Other     ] FAT/NTFS/HFS+/ReiserFS/...
```

I will select `ext2/ext3` and press `Enter`.

```
Please choose if all space needs to be analysed:
>[   Free    ] Scan for file from ext2/ext3 unallocated space only
 [   Whole   ] Extract files from whole partition
```

I will select `Free` and press `Enter`.

```
Directory /tmp/files
>drwxr-xr-x  1000  1000        40 28-Mar-2024 22:51 .
 drwxrwxrwt     0     0      1000 28-Mar-2024 22:51 ..
```

I will select the directory and press `C` to continue.

```
62 files saved in /tmp/files/recup_dir directory.
Recovery completed.
```

Now that's a whole bunch of files. Press `Enter` one last time to quit. Let's see what we got:

```
[steve@todo ctf-not_a_bad_day]$ ls /tmp/files/recup_dir.1/
f0017410.elf  f0017538.elf  f0017666.elf  f0017794.elf  f0017922.elf  f0018050.elf  f0018178.elf  f0018306.elf  f0020482.elf  f0020610.elf  f0020738.elf  f0020866.elf  f0020994.elf  f0021122.elf  f0021250.elf  f0021378.elf
f0017442.elf  f0017570.elf  f0017698.elf  f0017826.elf  f0017954.elf  f0018082.elf  f0018210.elf  f0018338.elf  f0020514.elf  f0020642.elf  f0020770.elf  f0020898.elf  f0021026.elf  f0021154.elf  f0021282.elf  f0021410.elf
f0017474.elf  f0017602.elf  f0017730.elf  f0017858.elf  f0017986.elf  f0018114.elf  f0018242.elf  f0018370.elf  f0020546.elf  f0020674.elf  f0020802.elf  f0020930.elf  f0021058.elf  f0021186.elf  f0021314.elf  report.xml
f0017506.elf  f0017634.elf  f0017762.elf  f0017890.elf  f0018018.elf  f0018146.elf  f0018274.elf  f0018402.elf  f0020578.elf  f0020706.elf  f0020834.elf  f0020962.elf  f0021090.elf  f0021218.elf  f0021346.elf
```

Those elf files look interesting. Time to run one:

```
[steve@todo ctf-not_a_bad_day]$ chmod +x /tmp/files/recup_dir.1/f0017410.elf 
[steve@todo ctf-not_a_bad_day]$ /tmp/files/recup_dir.1/f0017410.elf 
0: H
```

Seems like a character from the flag? A little awk magic is all we need:

```
[steve@todo ctf-not_a_bad_day]$ for elf_file in /tmp/files/recup_dir.1/*.elf; do chmod +x "$elf_file" && "$elf_file" | awk -F ": " '{print $1, $2}'; done | sort -n | awk '{print $2}' | tr -d '\n'
HCSC24{nbd_1s_4_SiCK_SyS4dm1n_t00l_f0r_r3m0t3_0s_1n57all4t10n}
```

And there we have it. The flag is `HCSC24{nbd_1s_4_SiCK_SyS4dm1n_t00l_f0r_r3m0t3_0s_1n57all4t10n}`.

A fully automated solver example can be found [here](poc.sh).

</details>