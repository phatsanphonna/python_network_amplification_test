from scapy.all import *
from scapy.layers.inet import IP, TCP

ADDRESS = "127.0.0.1"
DPORT = 80

SEND_COUNT = 1
PAYLOAD_SIZE = 1024


def tcp_syn_with_payload(dst: str, dport: int) -> Packet:
    ip = IP(dst=dst)
    tcp = TCP(dport=dport, sport=RandShort(), flags="S")

    payload = b"x" * PAYLOAD_SIZE

    pkt = ip / tcp / payload
    return pkt


if __name__ == "__main__":
    pkt = tcp_syn_with_payload(ADDRESS, DPORT)
    pkt.show()

    for _ in range(SEND_COUNT):
        send(pkt)
