inp = b"1c0111001f010100061a024b53535009181c"
xor_w = b"686974207468652062756c6c277320657965"
result = b"746865206b696420646f6e277420706c6179"

# Write a function that takes two equal-length buffers and produces their XOR combination.



import base64

def hex_to_base64(hex_bytes):
    return base64.b64encode(base64.b16decode(hex_bytes.upper()))


def xor(h1: bytes, h2: bytes) -> bytes:
    result = [hex1 ^ hex2 for hex1, hex2 in zip(h1, h2)]
    print(result)




if __name__ == "__main__":
    xor(inp, xor_w)