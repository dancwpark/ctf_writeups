from pwn import *

target = remote("chall.csivit.com", 30827)
#target = process("./RickNMorty")

while True:
    line = target.recvline().strip().split()
    if line[0].isalnum() == False:
        break
    a = int(line[0])
    b = int(line[1])
    result = math.gcd(a, b)
    result = math.factorial(result + 3)
    target.sendline(str(result))

print(target.recvuntil("!"))
print(target.recvuntil("}"))
