from _common import script

packets = [bytes(((i * 31 + j * 17) & 0xff) for i in range(257 + j)) for j in range(8)]
PPlayScript = script("udp_random_datagram_sequence", packets, "cs" * 4)
