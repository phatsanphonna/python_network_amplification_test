from scapy.all import *
from scapy.layers.inet import IP, TCP

ADDRESS = "127.0.0.1"
DPORT = 80

SEND_COUNT = 1


def tcp_invalid_ttl(dst: str, dport: int) -> Packet:
    ip = IP(dst=dst, ttl=128)
    tcp = TCP(dport=dport, sport=RandShort())

    pkt = ip / tcp
    return pkt


if __name__ == "__main__":
    pkt = tcp_invalid_ttl(ADDRESS, DPORT)
    pkt.show()

    for _ in range(SEND_COUNT):
        send(pkt)
