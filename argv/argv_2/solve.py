#!/usr/bin/env python

import angr

def main():
   # Pretty much completely stolen from ais3_crackme/solve.py
   project = angr.Project("./argv_2")

   # Bytes * 8 (because bits)
   argv1 = angr.claripy.BVS("argv1",100*8)
   init_state = project.factory.path(args=["./argv_2",argv1])
   pg = project.factory.path_group(init_state)

   pg.explore(find=0x004006b1, avoid=[0x00400669, 0x4006c7])
   found = pg.found[0]
   print "Found %d possibilities" % len(pg.found)
   return found.state.se.any_str(argv1)
   


if __name__ == '__main__':
    print(repr(main()))
