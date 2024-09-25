import sys

lookup1 = "\n \"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz"
lookup2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"

chars = ""

from fileinput import input
for line in input():
    chars += line

out = ""
prev = 0
for char in chars:
    cur = lookup2.index(char)
    idx = (cur + prev) % 40
    out += lookup1[idx]
    prev = idx


print(out)