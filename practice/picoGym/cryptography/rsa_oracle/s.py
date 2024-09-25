from pwn import *

context.log_level='critical'
port = 49329
p = remote("titan.picoctf.net", port)

p.recvuntil(b"decrypt.")

with open("password.enc") as file:
    c = int(file.read())

c = 873224563026311790736191809393138825971072101706285228102516279725246082824238887755080848591049817640245481028953722926586046994669540835757705139131212
p.sendline(b"E")
p.recvuntil(b"keysize): ")
p.sendline(b"\x02")
p.recvuntil(b"mod n) ")

c_a = int(p.recvline())

p.sendline(b"D")
p.recvuntil(b"decrypt: ")
p.sendline(str(c_a*c).encode())
p.recvuntil(b"mod n): ")

password = int(p.recvline(), 16) // 2
print(password)
password = password.to_bytes(len(str(password))-7, "big").decode("utf-8")

print("Password:", password)