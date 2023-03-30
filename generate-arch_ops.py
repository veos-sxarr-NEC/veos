#!/usr/bin/python3

from __future__ import print_function
import io, re, sys

# VEOS_ARCH_DEP_FUNC(archname, funcptr, impl)
PATTERN = '\s*VEOS_ARCH_DEP_FUNC\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)\s*'
REGEX = re.compile(PATTERN)

def generate(fname, archname, impllist):
  with io.open(fname, 'r') as f:
    for line in f:
      m = REGEX.match(line)
      if m:
         (a, fpname, implname) = m.group(1, 2, 3)
         if a == archname:
            impllist.append((fpname, implname))

def output(arch, name, funcs):
  print('/* GENERATED */\n#include <veos_arch_ops.h>')
  # declaration
  for f in funcs:
    print('extern __typeof(*((struct veos_arch_ops *)0)->%s) %s;' % f)

  print('const struct veos_arch_ops %s = {' % name)

  for f in funcs:
    print("\t.%s = %s," % f)

  print('};')

def main(args):
  archname = args[1]
  name = args[2]
  impllist = []
  for f in args[3:]:
    generate(f, archname, impllist)

  output(archname, name, impllist)
  return 0

sys.exit(main(sys.argv))
