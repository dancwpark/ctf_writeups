# TSGCTF 2020 -- Reverse-ing

Even though this is a reversing challenge, I thought I'd try to do the least amount of work and use Angr. 
Because this was labeled as an `easy` challenge, writing the angr solve script was also `easy`.

## Walkthrough
First, I ran `file reversing` to check whether or not the executable was stripped. This returned
```
reversing: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

I also did a cursory check of the binary using `Binary Ninja` to make sure there was nothing too complicated going on 
which would make the symbolic execution take too long.

With these done, I began writing the python script.

## Angr Solve
The script is included in my [repo](https://github.com/re-sejong/ctf_writeups/tree/master/TSGCTF2020/reverse-ing), but is also below:
```Python
import angr
import claripy
import time

# Just for logging time
begin = time.time()

p = angr.Project('reversing')
# Guessing Input size to be less than 50
flag_chars = [claripy.BVS('flag%d' %i, 8) for i in range(50)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

st = p.factory.full_init_state(
       args=['.reversing'],
       add_options=angr.options.unicorn,
       stdin=flag,
       )
sm = p.factory.simulation_manager(st)
sm.run()

out = b''
for pp in sm.deadended:
  out = pp.posix.dumps(1)
  if b'correct' in out:
    print(pp.posix.dumps(0))
    break

end = time.time()
print("Time Elapsed: {}".format(end-begin))
```
Running this gives us the solution!

Flag: `TSGCTF{S0r3d3m0_b1n4ry_w4_M4wa77e1ru}`
Time elapsed: 137.10 seconds
