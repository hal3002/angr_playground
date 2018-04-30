#!/usr/bin/env python

import angr
import string
import claripy

def main():
    project = angr.Project("./binary-secrets-x32")
    argv1 = claripy.BVS("argv1",20*8)
    st = project.factory.full_init_state(args=["./binary-secrets-x32", argv1])

    # Limit argv to only printable numerics
    for k in argv1.chop(8):
        st.add_constraints(k >= 0x30) 
        st.add_constraints(k <= 0x39) 

    sm = project.factory.simulation_manager(st)
    sm.explore(find=lambda s: "Woot" in s.posix.dumps(1))

    if sm.found:
        s = sm.found[0]
        return "Solution found - ARGV: %s STDIN: %s" % (s.state.se.eval(argv1, cast_to=str), s.posix.dumps(0)[:13])
    else:
        return "No solution found"

if __name__ == '__main__':
    print(repr(main()))
