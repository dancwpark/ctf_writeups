# CSICTF2020 - Blaise

## Description
`I recovered a binary from my teacher's computer. I tried to reverse it but I couldn't.`

## Analysis
First, I ran the code.

```Shell
d@d:~$ ./bliase
16
```

At this point, it was not clear what the executable did or wanted, so I entered random numbers until the process finished. It ended up exiting with no message.

Unsure what the binary did, I decompiled it with Ghidra. Below is the `main` function after some tidying:

```C
int main(void) {
    time_t rseed;
    ulong x;

    setbuf(stdout,(char *)0x0);
    setbuf(stdin,(char *)0x0);
    setbuf(stderr,(char *)0x0); 
    
    rseed = time((time_t *)0x0);
    srand((uint)rseed);
    x = display_number(0xf,0x14);
    process((int)x);
    return 0  
}
```

`main` sets a seed for a random number generator and calls `display_number` (decompiled below).

```C
ulong display_number(int arg1,int arg2)

{
  int x;
  uint ret;
  
  x = rand();
  ret = arg1 + x % ((arg2 - arg1) + 1);
  printf("%d\n",(ulong)ret);
  return (ulong)ret;
}
```

`display_number` just uses the random number generator to get a number.

Following the list of functions called in `main`, I looked at `process` (decompiled below).

```C
int process(int x)

{
  long key;
  long in_FS_OFFSET;
  int local_1c;
  int i;
  long lVar1;
  bool flag;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  flag = true;
  i = 0;
  while (i <= x) {
    __isoc99_scanf();
    key = C(x,i);
    if ((int)key != local_1c) {
      flag = false;
    }
    i = i + 1;
  }
  if (flag) {
    system("cat flag.txt");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

I assumed the `__isoc99_scanf()` call wrote into `local_1c`. Usually, there should be parameters given for the `__isoc99_scanf()` (or atleast in IDA). 

Assuming the previous, it is clear that we are given a challenge `x` times, where `x` is the randomly generated number from `display_number`. At each iteration, the challenge generates `key` using function call `C(x, i)` and checks that the user input matches. If the `flag` remains `true` after the challenges, we get the flag. If any of the user's answers are incorrect, the `flag` is set to false. So, if we understand how `C` (below) works, we can automate the process of answering the challenges.

```C
long C(int x,int i)

{
  long a;
  long b;
  long c;
  
  a = f(x);
  b = f(i);
  c = f(x - i);
  return a / (b * c);
}
```

I then looked at `f`.

```C
long f(int d)

{
  int i;
  long result;
  
  result = 1;
  i = 2;
  while (i <= d) {
    result = i * result;
    i = i + 1;
  }
  return result;
}
```

It turned out that `f` is the factorial function and `C` is nCr, nCk, binomial coefficients, etc...

Understanding the executable better, we wrote the following script.

## Solution
The following script defines a function for computing nCr and uses it to interact and solve the challenges from `./blaise`.

```Python
from pwn import *
import operator as op
from functools import reduce

def ncr(n, r):
  r = min(r, n-r)
  num = reduce(op.mul, range(n, n-r, -1), 1)
  den = reduce(op.mul, range(1, r+1), 1)
  return num // den

target = remote("chall.csivit.com", 30808)
# local
# target = process("./blaise")

line = int(target.recvline().strip().split()[0])
for i in range(line+1):
  result = ncr(line, i)
  target.sendline(str(result))

print(target.recvuntil("}"))
```

Running this got us the flag!

```Shell
d@d:~/$ python3 solver.py
[+] Opening connection to chall.csivit.com on port 30808: Done
b"csictf{y0u_d1sc0v3r3d_th3_p4sc4l's_tr14ngl3}"
```
