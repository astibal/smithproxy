from _common import script

noise = bytes(((i * 73 + 19) & 0xFF) for i in range(16384))
PPlayScript = script("deterministic_noise", [noise, noise[::-1]], "cs")
