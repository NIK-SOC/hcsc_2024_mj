# Creeper or Griefer?

Easy OSINT like challenge.

> I set up a Minecraft server (`1.20.4`) for my friends initially using Hamachi, but we encountered lagging issues. Following a tutorial, I transitioned to a VPS and configured port forwarding, which significantly improved performance. However, on the same day, an unfamiliar player joined briefly, and since then, we've experienced a barrage of random players wreaking havoc on our server. The map was ravaged by lava and TNT, leading us to suspect hacking. I shut down the server for nearly a month and eventually sold the VPS, but I'm keen to uncover who was behind these malicious acts. Can you provide assistance?
>
> The IP was: `193.225.250.153`
>
> ## **NOTE**: Please refrain from attempting to access any services on the specified IP address. I assure you that there are no active services running there anymore. The challenge lies not in hacking into that specific IP, but in gathering information about the server. Also, please note that it is against the law to engage in any form of unauthorized access or attack.

## How to run

The challenge doesn't need these commands to be ran, unless you would like to get it cached with a different IP. In which case, you should make sure that port 25565 is open to the public and have it running for a few days before attempting to solve the challenge.

1. Clone the repo and cd to the root folder of the particular challenge
2. Build the image: `podman build -t ctf-creeper_or_griefer:latest .`
3. Run the image: `podman rm -f ctf-creeper_or_griefer:latest; podman run -it --rm --name ctf-creeper_or_griefer -p 25565:25565 ctf-creeper_or_griefer:latest`

<details>
<summary>Writeup (Spoiler)</summary>

Pretty much the only thing given to us is an IP address. We also know that the server was running Minecraft and that it has happened in the past. So we are probably looking for a crawler or a Minecraft server database.

If we look up `minecraft server crawler` in our favorite search engine and filter for the last year, one possible search result shows up from reddit: https://www.reddit.com/r/Minecraft/comments/143zufm/a_player_named_serverseeker_is_joining_my_server/

This could mean that the server was crawled by a bot called `ServerSeeker`. We can look up that name.

This is the site/API that shows up: http://api.serverseeker.net/

With the content:

```json
{"description":"ServerSeeker API","docs":"https://serverseeker.net/docs"}
```

Once we navigate to the docs, a familiar swagger UI shows up. Though first we need to authenticate in order to use the API. We can do that by clicking at the `Click here to get your API key` text. This navigates us to a Discord OAuth2 page. We can authorize the app and get our API key:

```json
{"api_key":"redacted"}
```

After that we can go back and click on the Authorize button in the top right corner. We can paste our API key in the `api_key` field and click Authorize. This means that we now have access to the API.

Time to call the `/server_info - Get info about a server` endpoint.

Seemingly it takes in similar syntax:

```json
{
  "ip": "109.123.240.84",
  "port": 25565
}
```

We can use swagger, but with our IP address. The port can stay on the default `25565`. So something like:

```json
{
  "ip": "193.225.250.153",
  "port": 25565
}
```

Let's try it out using swagger. We get the following response:

```json
{
  "as_domain": "gov.hu",
  "as_name": "KIFU (Governmental Info Tech Development Agency)",
  "asn": 1955,
  "continent_code": "EU",
  "continent_name": "Europe",
  "country_code": "HU",
  "country_name": "Hungary",
  "cracked": null,
  "description": "Epic gaming happens here§r",
  "is_bungee_spoofable": false,
  "is_modded": false,
  "last_seen": 1708473199,
  "max_players": 2024,
  "online_players": 420,
  "players": [
    {
      "last_seen": 1708473199,
      "name": "_tr4ces_everywhe",
      "uuid": "14347505-e5f4-433d-b7f5-f84150041272"
    },
    {
      "last_seen": 1708473199,
      "name": "re}",
      "uuid": "318331c8-a0fb-4fe9-8d77-21869be91315"
    },
    {
      "last_seen": 1708473199,
      "name": "HCSC24{y0u_l34ve",
      "uuid": "889841b3-88f0-4911-b12b-f0738cfae6e2"
    }
  ],
  "protocol": 765,
  "server": "193.225.250.153:25565",
  "version": "1.20.4"
}
```

And voilà! We have the flag in parts. All we have to do is guessing the right order of the individual chops. The flag is: `HCSC24{y0u_l34ve_tr4ces_everywhere}`.

</details>
