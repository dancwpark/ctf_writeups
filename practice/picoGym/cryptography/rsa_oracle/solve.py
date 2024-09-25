from pwn import *

host = "titan.picoctf.net"
port = 49329

# https://crypto.stackexchange.com/questions/2323/how-does-a-chosen-plaintext-attack-on-rsa-work/2331#2331

r = remote(host, port)

a = r.recvuntil(b"decrypt")
r.sendline(b"E")
a = r.recv()
r.sendline(b"\x02")
r.recvuntil(b"mod n)")
a = int(r.recvline().strip())

c1 = 873224563026311790736191809393138825971072101706285228102516279725246082824238887755080848591049817640245481028953722926586046994669540835757705139131212
attack = str(c1 * a).encode()

r.sendline(b"D")
r.recvuntil(b"decrypt: ")
r.sendline(attack)
r.recvuntil(b"decrypted ciphertext as hex (c ^ d mod n): ")
a = r.recvline().strip()
a = int(a, 16) // 2
print(a)
# https://stackoverflow.com/questions/846038/convert-a-python-int-into-a-big-endian-string-of-bytes
print(a.to_bytes(len(str(a))-7, "big").decode("utf-8"))


# 92d53
# openssl enc -aes-256-cbc -d -in secret.enc
# picoCTF{su((3ss_(r@ck1ng_r3@_92d53250}


# openssl treats byte objects as big endian...
# https://stackoverflow.com/questions/49650932/why-does-openssl-operate-in-big-endian-format