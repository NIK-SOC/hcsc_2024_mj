# Prequel

Medium difficulty pwn challenge. Part Two.

> 💀 We greet you and you steal our flag? That's how much you care? Really? Nowadays you can't even leave a debug function in your code without it being abused. Noted... And of course removed. We are safe now! Good morning to you too!
>
> The port is 3117.

## How to run

The image was tested with podman, but should work fine with docker as well.

0. Clone the repo and cd to the root folder of the particular challenge
1. Build the image: `podman build -t ctf-prequels-revenge:latest .`
2. Run the image: `podman rm -f ctf-prequels-revenge:latest; podman run --name ctf-prequels-revenge -it --rm -p 3117:3117 -e CHALLENGE_PORT=3117 ctf-prequels-revenge:latest`

Connect on port 3117.

<details>
<summary>Writeup (Spoiler)</summary>

Our favorite decompiler reveals that there aren't many changes, just that the `print_debug_flag` along with the `SELECT flag FROM flag LIMIT ?;` is gone as well as the `messages_debug.db` file. But it's safe to assume that the goal is similar.

This time the version string is `102` however. We can still use that, but we need a SELECT query that will return the flag. To supply that, a good old trick to call `read` in our ROP payload will suffice. We can use the `.bss` section to store the SQL query.

I have prepared an exploit that does just that, you can find it in [poc.py](poc.py).

</details>