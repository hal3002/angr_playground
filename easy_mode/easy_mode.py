#!/usr/bin/env python

import angr
import claripy
import sys
import string
import simuvex

from optparse import OptionParser

def constrain_printable(state, argv1):
   for b in argv1.chop(8):
      state.add_constraints(
         claripy.And(claripy.UGE(b, 0x20), claripy.ULE(b, 0x7e)),
      )
      
def constrain_alpha_numeric(state, argv1):
   for b in argv1.chop(8):
      state.add_constraints(
         claripy.Or(
            claripy.And(claripy.UGE(b, 'a'), claripy.ULE(b, 'z')),
            claripy.And(claripy.UGE(b, 'A'), claripy.ULE(b, 'Z')),
            claripy.And(claripy.UGE(b, '0'), claripy.ULE(b, '9')),
         )
      )

def constrain_alpha_upper(state, argv1):
   for b in argv1.chop(8):
      state.add_constraints(
         claripy.Or(
            claripy.And(claripy.UGE(b, 'A'), claripy.ULE(b, 'Z')),
         )
      )

def constrain_alpha_lower(state, argv1):
   for b in argv1.chop(8):
      state.add_constraints(
         claripy.Or(
            claripy.And(claripy.UGE(b, 'a'), claripy.ULE(b, 'z')),
         )
      )

def constrain_numeric(state, argv1):
   for b in argv1.chop(8):
      state.add_constraints(
         claripy.Or(
            claripy.And(claripy.UGE(b, '0'), claripy.ULE(b, '9')),
         )
      )

def constrain_prefix(state, argv1, prefix):
   argv1_bytes = argv1.chop(8)
   
   for i in xrange(len(prefix)):
      state.add_constraints(argv1_bytes[i] == prefix[i])

def constrain_suffix(state, argv1, suffix):
   argv1_bytes = argv1.chop(8)

   for i in xrange(len(suffix)):
      state.add_constraints(argv1_bytes[len(argv1_bytes) - len(suffix) + i] == suffix[i])

def constrain_inputs(state, options, arg):
   if options.numeric: constrain_numeric(state, arg)
   if options.alpha_lower: constrain_alpha_lower(state, arg)
   if options.alpha_upper: constrain_alpha_upper(state, arg)
   if options.alpha_numeric: constrain_alpha_numeric(state, arg)
   if options.printable: constrain_printable(state, arg)
   if options.prefix: constrain_prefix(state, arg, options.prefix)
   if options.suffix: constrain_suffix(state, arg, options.suffix)
 
def solve(options):
   
   # Build a list of possible args
   args = [options.executable]

   for i in xrange(options.arguments):
      args.append(angr.claripy.BVS("argv%d" % i, options.input_length*8))

   project = angr.Project(options.executable)

   if options.remove_lazy:
      init_state = project.factory.entry_state(args=args, remove_options={simuvex.o.LAZY_SOLVES})
   else:
      init_state = project.factory.entry_state(args=args)
   
   # Constrain all of the arguments
   for arg in args[1:]:
      constrain_inputs(init_state, options, arg)

   # Constrain stdin as well
   for i in xrange(options.input_length):
      constrain_inputs(init_state, options, init_state.posix.files[0].read_from(1))
   init_state.posix.files[0].length = options.input_length
   
   # Who knows what this does?
   init_state.simplify()

   pg = project.factory.path_group(init_state)
   pg.explore(find=options.find, avoid=options.avoid)

   print "Found %d possibilities" % len(pg.found)
   if len(pg.found) > 0:
      for found in pg.found:
         found.state.simplify()
         
         # Dump input arguments
         if options.arguments > 0:
            for arg in args[1:]:
               print "%s: %s" % (arg, found.state.se.any_n_str(arg, options.results))
            
         # Dump stdin
         if options.stdin:
            try:
               print "STDIN: %s" % found.state.posix.dumps(0)
            except simuvex.s_errors.SimFileError:
               pass

         # Dump stdout
         try:
            print "STDOUT: %s" % found.state.posix.dumps(1)
         except simuvex.s_errors.SimFileError:
            pass

def main(options, args):
   for i in xrange(options.min_length, options.max_length + 1):
      options.input_length = i
      solve(options)
   
if __name__ == '__main__':
   
   parser = OptionParser()
   parser.add_option("-f", "--executable", dest="executable", type="string", help="The target executable. REQUIRED")
   parser.add_option("--find", dest="find", type="int", help="The address of the path to reach to win. REQUIRED")
   parser.add_option("--avoid", dest="avoid", action="append", type="int", help="The address of paths to avoid. This can be defined multiple times.")
   parser.add_option("-l", "--input-length", dest="input_length", type="int", help="Specifies the exact length of the input.")
   parser.add_option("-m", "--minimum-length", dest="min_length", type="int", help="Specifies a minimum length of the input. Must also include maximum length.")
   parser.add_option("-n", "--maximum-length", dest="max_length", type="int", help="Specifies a maximum length of the input. Must also include minimum length.")
   parser.add_option("--results", dest="results", type="int", help="How many possible matches to return.", default=10)

   parser.add_option("--arguments", dest="arguments", type="int", help="How many arguments to test the target with.", default=1)
   parser.add_option("--stdin", dest='stdin', action='store_true', default=False, help="Apply constraints and solve using stdin.")

   # Solution constraint options
   parser.add_option("-p", "--prefix", dest="prefix", type="string", help="Require solutions to start with PREFIX.")
   parser.add_option("-s", "--suffix", dest="suffix", type="string", help="Require solutions to end with SUFFIX.")
   parser.add_option("--numeric", dest="numeric", action="store_true", default=False, help="Constrain solutions to numeric only.")
   parser.add_option("--alpha-lower", dest="alpha_lower", action="store_true", default=False, help="Constrain solutions to alpha lowercase only.")
   parser.add_option("--alpha-upper", dest="alpha_upper", action="store_true", default=False, help="Constrain solutions to alpha uppercase only.")
   parser.add_option("--alpha-numeric", dest="alpha_numeric", action="store_true", default=False, help="Constrain solutions to alpha, lowercase, and uppercase only.")
   parser.add_option("--printable", dest="printable", action="store_true", default=False, help="Constrain solutions to python's string.printable.")
   parser.add_option("--remove-lazy", dest="remove_lazy", action="store_true", default=False, help="Remove LAZY solve option.")

   (options, args) = parser.parse_args()

   if options.executable is None: 
      sys.exit("executable is required.")
   if options.find is None:
      sys.exit("find path is required.")

   if not options.input_length:
      if not options.min_length or not options.max_length:
         sys.exit("You must specify either an input-length or both a minimum and maximum length")
      elif options.min_length >= options.max_length:
         sys.exit("Maximum length must be greater than minimum length")
   else:
      if options.min_length or options.max_length:
         sys.exit("Do not specify a minimum or maximum length and a specific length")
      else:
         options.min_length = options.input_length
         options.max_length = options.input_length

   main(options, args)
