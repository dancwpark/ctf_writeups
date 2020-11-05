---
title: 'AUCTF2020 Sora'
date: 2020-04-09
permalink: /posts/2020/09/auctf-sora/
tags:
  - ctf
  - angr
---


This was another simple reverse engineering task. It can also be found on the CTF hosts website linked in the last post). Lucky for me, I have been trying to learn and incorporate [angr](https://angr.io/) more into my workflow. 

## Write-up
I started by just looking at the disassembly of the file. See the image below!
![alt text](https://github.com/dancwpark/ctf_writeups/AUCTF2020/images/autctf2020/sora-dis.PNG "auctf sora dis")

One branch leads to the `print_flag` function, whereas the other branch leads to printing "That's not it!". It is pretty obvious which path we want to take. Looking at the block before the branching paths, we can see that there is a call to a function `encrypt`. Instead of looking at that (which includes a bunch of transformations on our input), we can use `angr` to solve this challenge for us. 

Things we need:
* The address of the basic block (or state) we want to be in.
* (Optional) Addresses of states we would like to avoid.

Using IDA (because it's already open), I found the 'good' state to be at offset `0x12A5`. Because I know we do not want to go down the 'bad' state, I noted that its address is `0x12BC`. 

All that is left is to write and run our `angr` script.

{% gist 534b82fa182684c6e13601e6551a8a0f %}

One thing to note is that the 'good' and 'bad' states' addresses are offset by 0x4000000. This is because `angr` loads the base address as 0x4000000 by default. This can be changed when loading the binary if you should desire.

After running the script, we get `b'75y"7o"%r($._m(G\x00\x00\x00\x04\x00\x01\x00\x00\x00\x00@\x00\x00'` as output. We take the key (`b'key'`) and use it as our input to the hosted challenge, giving us the flag:

`auctf{that_w@s_2_ezy_29302}`
