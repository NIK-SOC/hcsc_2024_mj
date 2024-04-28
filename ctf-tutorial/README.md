# Tutorial

Not really a challenge, just a per user Docker container tutorial. Runs a simple nginx share with the flag.

## How to run

The image was tested with podman, but should work fine with docker as well.

1. Clone the repo and cd to the root folder of the particular challenge
2. Build the image: `podman build -t ctf-tutorial:latest .`
3. Run the image: `podman rm -f ctf-tutorial:latest; podman run -it --rm -p 8080:80 ctf-tutorial:latest`