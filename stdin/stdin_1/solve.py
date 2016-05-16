#!/usr/bin/env python

import angr

def main():
   # Pretty much completely stolen from csaw_wyvern/solve.py
   project = angr.Project("./stdin_1")
   init_state = project.factory.path(args=["./argv_2"])
   pg = project.factory.path_group(init_state)

   pg.explore(find=0x00400783, avoid=0x00400799)
   found = pg.found[0]
   print "Found %d possibilities" % len(pg.found)
   return found.state.posix.dumps(0)

if __name__ == '__main__':
    print(repr(main()))
