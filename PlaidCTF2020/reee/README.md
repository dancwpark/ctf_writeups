# PlaidCTF2020 reee

I think this was one of the more easier reversing challenges from PlaidCTF. Regardless, I think it would still be beneficial for me to make this write-up as it is the first time I really used Ghidra instead of IDA on a task.

## Analysis
I began by loading up the binary as usual in Ghidra.

One thing right off the bat that I noticed is that Ghidra does not automatically name a `main` function. When loading up the binary in IDA and Binary Ninja, both automatically renamed the function at `0x40064e` as 'main'. This isn't a huge deal, but I still found it a little strange. It's easy enough, however, to know which of the `FUN_00400*` is the `main` function by looking at the `entry` function.

![entry2main](https://dancwpark.github.io/images/plaidctf2020/entry.PNG "entry2main")

After doing some general reversing (looking at variables, functions, etc...), `main` looked like the following image.

![main_re](https://dancwpark.github.io/images/plaidctf2020/main_re.PNG "main_re")

I renamed two functions to `convert` and `check_flag`. `convert` was a little odd, so I decided to ignore it for now. 

![convert](https://dancwpark.github.io/images/plaidctf2020/convert.PNG "convert")

![checkflag](https://dancwpark.github.io/images/plaidctf2020/check_flag.PNG "check_flag")

`check_flag` led to bad instructions, which was the first red flag on something fishy going on. Looking at the usage of `convert`, it was being run using `check_flag` as an argument.

{% highlight c %}
i = 0
while (i < 31337) {
    j = 0;
    while (j < 552) {
        uVar1 = convert((byte)check_flag[j]);
        check_flag[j] = SUB81(uVar1, 0);
        j = j + 1;
    }
    i = i + 1;
}

Var2 = check_flag();
{% endhighlight %}

The above snippet takes 552 bytes of the `check_flag` function and uses them as input to `convert`. This process is then repeated for a total of 31337 runs. After this translation, `check_flag` is run. This means that the current `check_flag` function in our Ghidra decompiler view is incorrect because it has not yet been `convert`ed. 

I thought about reversing the `convert` function, fully understand it, and apply it by hand to the first 552 bytes of `check_flag`... but that seemed a little to tedious. So, I just used GDB.

## Memory Dump via GDB
Using GDB, we can run the code so that the `check_flag` function is `convert`ed and then dump the function. Looking at the disassembly, I found the the `check_flag()` call occurs at `0x4006db` and set a breakpoint at the address. At the break point, the function should have been decrypted, so I dumped it using the command: `dump binary memory check_flag.bin 0x4006e5 0x040093f`, saving the dump to `check_flag.bin`. Note that `0x4006ef` and `0x40093f` are the start and end addresses of `check_flag` found usin Ghidra.

![gdb](https://dancwpark.github.io/images/plaidctf2020/gdb.png "gdb")

Because the function  `convert` does not alter the function's size, we can simply replace the function in `./reee`. This can be done easily through python and splicing usingn the start and end addresses of `check_flag`. Note that the actual addresses would be `0x6ef` and `0x93f` as GDB (and other binary analysis tools) automatically loads programs with a base address of `0x4000000`. I belive IDA and Binary Ninja can automatically use the `*.bin` file to aid in the analysis of encrypted functions, but I was not able to find such a shortcut for Ghidra. 

## Analysis Part 2: Electric Boogaloo
Now taht we have a new file with unencrypted `check_flag`, we can load it up on Ghidra. For the sake of my fingers, I didn't rename variables and the like again unless it was something new.

Our `check_flag` function became the following:

![check_old](https://dancwpark.github.io/images/plaidctf2020/check_flag_old.PNG "Check old")

and our new function `check_flag_new` is:

![check_new](https://dancwpark.github.io/images/plaidctf2020/check_flag_new.PNG "Check new").

So... what does this new function `check_flag_new` do?

It took me WAY longer than I would like to admit, but I eventually found out that the first `while` loop is just finding the length of `input`. 

The second `while loop` does the following (in pythonic pseudocode):
{% highlight python %}
key = 0x50
for i in range(1337):
    for j in range(len(input)):
        input[j] = input[j] ^ key
        key = key ^ input[j]
{% endhighlight %}

After this transformation, the result is compared to `&DAT_004008eb`. If the two are equal, `True` is returned all the way up to the `main` function, resulting in `puts("Correct")`.

Finding the length of `input` is important as it will change the value of our `key` over time. To be honest, I saw the byte dump starting at `0x4008eb` and copied until I saw `00`, or what I assumed would be interpreted as a null byte terminator. This gives us the encrypted key as 

`48 5f 36 35 35 25 14 2c 1d 01 03 2d 0c 6f 35 61 7e 34 0a 44 24 2c 4a 46 19 59 5b 0e 78 74 29 13 2c`

which is 33 bytes long.

The only thing left would be to reverse the process that led to our encrypted key. But, that would take 1337 * 33 * 2 computations... We know that the flag is in the format `pctf{*}`, so we can start our chain of `xor`s with `}`... but, again, this is too tedious. So, let's use another tool to automate this for us.

## Automate with Z3
Using Z3, we can set constraints and solve for each byte of our flag. I won't go too deep into how it works, but my script is below.

```Python
from z3 import *
raw_flag = b"\x48\x5f\x36\x35\x35\x25\x14\x2c\x1d\x01\x03\x2d\x0c\x6f\x35\x61\x7e\x34\x0a\x44\x24\x2c\x4a\x46\x19\x59\x5b\x0e\x78\x74\x29\x13\x2c"

key = 0x50
s = Solver()
# flag symbolic vector
flag = [BitVec('byte%i' % i,8) for i in range(33)] 
# symbolic vector for encryption
inRAX = [BitVec('byte%i' % i,8) for i in range(33)]
# both have the same names for each symbolic 
#  byte to denote their initial equivalence

# 'check_flag'
for i in range(1337):
    for j in range(33):
        inRAX[j] = inRAX[j] ^ key
        key = key ^ inRAX[j]
# additional constraints
for i in range(33):
    # raw data should be output of encryption
    s.add(raw_flag[i] == inRAX[i])
    # flag will be printable ascii
    s.add(And(flag[i] >= 0x20, flag[i] <= 0x7f))
solver.add(flag[0] == ord("p"))                       
solver.add(flag[1] == ord("c"))                       
solver.add(flag[2] == ord("t"))                       
solver.add(flag[3] == ord("f"))                       
solver.add(flag[4] == ord("{"))                       
solver.add(flag[-1] == ord("}"))

if s.check() == sat:
    print("".join([chr(s.model()[c].as_long()) for c in flag]))
else:
    print("Failed")
```

Running this outputs:

`pctf{ok_nothing_too_fancy_there!}`
