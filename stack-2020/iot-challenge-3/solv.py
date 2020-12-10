import angr
import claripy

p = angr.Project("./dude_my_chips")

good = 0x10798
bad = 0x107A8

flag_len = 8
flag_chars = [claripy.BVS(f"flag_char{i}", 8) for i in range(flag_len)]
flag = claripy.Concat(*flag_chars)

state = p.factory.entry_state(stdin=flag)
sm = p.factory.simulation_manager(state)
sm.explore(find=good, avoid=bad)
if len(sm.found) > 0:
    for found in sm.found:
        print(found.posix.dumps(0))
