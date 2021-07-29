#!/usr/bin/env python3

"""This script splits httplib.h into .h and .cc parts."""

import argparse
import os
import sys

border = '// ----------------------------------------------------------------------------'

args_parser = argparse.ArgumentParser(description=__doc__)
args_parser.add_argument(
    "-e", "--extension", help="extension of the implementation file (default: cc)",
    default="cc"
)
args_parser.add_argument(
    "-o", "--out", help="where to write the files (default: out)", default="out"
)
args = args_parser.parse_args()

cur_dir = os.path.dirname(sys.argv[0])
with open(cur_dir + '/httplib.h') as f:
    lines = f.readlines()

python_version = sys.version_info[0]
if python_version < 3:
    os.makedirs(args.out)
else:
    os.makedirs(args.out, exist_ok=True)

in_implementation = False
h_out = args.out + '/httplib.h'
cc_out = args.out + '/httplib.' + args.extension
with open(h_out, 'w') as fh, open(cc_out, 'w') as fc:
    fc.write('#include "httplib.h"\n')
    fc.write('namespace httplib {\n')
    for line in lines:
        is_border_line = border in line
        if is_border_line:
            in_implementation = not in_implementation
        elif in_implementation:
            fc.write(line.replace('inline ', ''))
        else:
            fh.write(line)
    fc.write('} // namespace httplib\n')

print("Wrote {} and {}".format(h_out, cc_out))
