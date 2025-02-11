from scapy.all import *
from scapy.layers.inet import IP, UDP

ADDRESS = "127.0.0.1"
DPORT = 80

SEND_COUNT = 1


def udp_iplen_mismatch(dst: str, dport: int) -> Packet:
    ip = IP(dst=dst)
    udp = UDP(dport=dport, sport=RandShort())

    payload = b"Hello, World!"

    payload_len = len(payload) + 8  #  8 bytes for UDP header

    udp.len = payload_len - 12

    pkt = ip / udp / payload

    return pkt


if __name__ == "__main__":
    pkt = udp_iplen_mismatch(ADDRESS, DPORT)
    pkt.show()

    for _ in range(SEND_COUNT):
        send(pkt)
