# Useful functions


```Python
import base64

def hex_to_base64(hex_bytes: bytes) -> bytes:
    """
    Input assumes that hex_bytes is a byte string, e.g., b"AAAA" of hex.
    The function will ouput a byte string of the base64 equivalent.
    """
    return base64.b64encode(base64.b16decode(hex_bytes.upper()))
```