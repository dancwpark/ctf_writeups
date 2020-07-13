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
