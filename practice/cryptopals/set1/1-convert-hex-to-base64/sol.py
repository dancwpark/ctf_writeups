hex_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
answer = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

# Always operate on raw bytes, never on encoded strings
# Only use hex and base64 for pretty-printing
#

import base64

def hex_to_base64(hex_bytes):
    return base64.b64encode(base64.b16decode(hex_bytes.upper()))


def main():
    result = hex_to_base64(hex_string)
    if result != answer:
        print("wrong")
    else:
        print("correct")


if __name__ == "__main__":
    main()
