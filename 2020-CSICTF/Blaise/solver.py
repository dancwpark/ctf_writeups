from pwn import *
import operator as op
from functools import reduce

def ncr(n, r):
    r = min(r, n-r)
    numer = reduce(op.mul, range(n, n-r, -1), 1)
    denom = reduce(op.mul, range(1, r+1), 1)
    return numer // denom

target = remote("chall.csivit.com", 30808)
#target = process("./blaise")


line = int(target.recvline().strip().split()[0])

for i in range(line+1):
    result = ncr(line, i)
    target.sendline(str(result))

#print(target.recvuntil("!"))
print(target.recvuntil("}"))
