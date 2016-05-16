#!/usr/bin/env python

import angr

def main():
    #project = angr.Project("./argv_1", load_options={'auto_load_libs': False})
   project = angr.Project("./argv_1")

   # Bytes * 8 (because bits)
   argv1 = angr.claripy.BVS("argv1",100*8)
   init_state = project.factory.path(args=["./arg_1",argv1])
   pg = project.factory.path_group(init_state)

   pg.explore(find=0x400706, avoid=[0x400669, 0x40070d])
   found = pg.found[0]
   print "Found %d possibilities" % len(pg.found)
   return found.state.se.any_str(argv1)
   


if __name__ == '__main__':
    print(repr(main()))
