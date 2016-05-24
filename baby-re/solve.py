#!/usr/bin/env python

import angr
import simuvex
import claripy
import sys

input_bytes = []

# Basically nop'ing on these calls
def ignore(state):
   state.regs.rax = 0
   
# We know that scanf is just looking for a %d so just create a symbolic 32-bit to feed back
# and then we can avoid scanf all together
def scanf(state):
   b = claripy.BVS("input_%d" % len(input_bytes), 32)
   input_bytes.append(b)
   state.memory.store(state.regs.rsi, b)
   pass

def main():
   project = angr.Project("./baby-re", load_options={'auto_load_libs': False})
   init_state = project.factory.entry_state(remove_options={simuvex.s_options.LAZY_SOLVES})

   # Address of main to make calculating these next hooks easier
   main_address = 0x4025e7

   # printfs we don't care about
   for offset in [0x28, 0x5c, 0x94, 0xcc, 0x104, 0x13c, 0x174, 0x1ac, 0x1e4, 0x21c, 0x254, 0x28c, 0x2c4]:
      print "Hooking printf at 0x%x" % (main_address + offset)
      project.hook(main_address + offset, ignore, length=5)

   # flushes we don't care about
   for offset in [0x37, 0x6b, 0xa3, 0xdb, 0x113, 0x14b, 0x183, 0x1bb, 0x1f3, 0x22b, 0x263, 0x29b, 0x2d3]:
      print "Hooking flush at 0x%x" % (main_address + offset)
      project.hook(main_address + offset, ignore, length=5)

   # Fake scanf
   for offset in [0x4d, 0x85, 0xbd, 0xf5, 0x12d, 0x165, 0x19d, 0x1d5, 0x20d, 0x245, 0x27d, 0x2b5, 0x2ed]:
      print "Hooking scanf at 0x%x" % (main_address + offset)
      project.hook(main_address + offset, scanf, length=5)

   pg = project.factory.path_group(init_state)

   # Avoid all of the mov rax, 0 blocks at the end of CheckSolution
   pg.explore(find=0x40294b, avoid=[0x4025e0, 0x402941, 0x401697, 0x4017DF, 0x40192B, 0x401A76, 0x401BC2, 0x401D11, 0x401E5D, 0x401FAB, 0x4020F3, 0x40223F, 0x402383, 0x4024A4, 0x4025C5])

   # We should be after the "flag is" block
   found = pg.found[0]
   print "Found %d possibilities" % len(pg.found)
   
   if len(pg.found) > 0:
      return found.state.posix.dumps(1)

if __name__ == '__main__':
    print(repr(main()))
