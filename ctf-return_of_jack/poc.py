from scapy.all import sr
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.all import conf
from scapy.all import L3RawSocket
from string import ascii_uppercase

# required for lo interface as per https://stackoverflow.com/a/75487612
# not required for real environment and won't work on non lo, use for testing
conf.L3socket = L3RawSocket


def main():
    print()
    characters = []
    i = 0
    while not characters or characters[-1] != "}":
        for c in ascii_uppercase + "{}_24":
            # EDIT THE VALUES ABOVE
            local_ipv4_addr = "127.0.0.1" # your local ipv4 address goes here (from the interface you want to use, e.g. wlp1s0)
            remote_ipv4_addr = "127.0.0.1" # remote ipv4 address of the challenge server

            local_ipv6_addr = "2001:470:6d:d6::1336" # anything but 2001:470:6d:d6::1337 will work, 1337 is for hints
            remote_ipv6_addr = "2a00:1450:400d:808::200e" # can be whatever, machine will respond here
            #######################

            ip4_layer = IP(
                src=local_ipv4_addr, dst=remote_ipv4_addr, proto=41, ttl=255, version=4
            )
            ip6_layer = IPv6(version=6, src=local_ipv6_addr, dst=remote_ipv6_addr)

            icmp6_layer = ICMPv6EchoRequest(id=i, seq=ord(c))

            packet = ip4_layer / ip6_layer / icmp6_layer
            results, _ = sr(packet, iface="lo", timeout=0.2, verbose=False) # change iface to your interface
            if results:
                print("\033[A", end="")
                characters.append(c)
                print("".join(characters))
                i += 1
                break
        else:
            raise Exception("We started re-iterating over the characters. This should not happen.")
    print("Flag:", "".join(characters))


if __name__ == "__main__":
    main()
