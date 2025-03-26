#!/usr/bin/env python3

"""This script splits httplib.h into .h and .cc parts."""

import argparse
import os
import re
import sys
import typing

BORDER: str = '// ----------------------------------------------------------------------------'
INLINE_PATTERN = re.compile(r'\binline\s+')

args_parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
args_parser.add_argument(
    "-e", "--extension", help="extension of the implementation file (default: cc)",
    default="cc"
)
args_parser.add_argument(
    "-o", "--out", help="where to write the files (default: out)", default="out"
)
args: argparse.Namespace = args_parser.parse_args()

cur_dir: str = os.path.dirname(sys.argv[0])
lib_name: str = 'httplib'
header_name: str = os.path.join(lib_name + '.h')
source_name: str = os.path.join(lib_name + '.' + args.extension)
in_file: str = os.path.join(cur_dir, lib_name + '.h')
h_out: str = os.path.join(args.out, header_name)
cc_out: str = os.path.join(args.out, source_name)

# Check if we need to split
do_split: bool = True
if os.path.exists(h_out) and os.path.exists(cc_out):
    in_time: float = os.path.getmtime(in_file)
    out_time: float = max(os.path.getmtime(h_out), os.path.getmtime(cc_out))
    do_split = in_time > out_time

if do_split:
    # Read entire file at once
    with open(in_file) as f: # type: typing.TextIO
        content: str = f.read()

    os.makedirs(args.out, exist_ok=True)

    # Pre-allocate buffers
    header_lines: typing.List[str] = []
    impl_lines: typing.List[str] = [
        '#include "httplib.h"\n',
        'namespace httplib {\n'
    ]

    in_implementation: bool = False
    border_stripped: str = BORDER.strip()

    for line in content.splitlines(keepends=True):
        if line.strip() == border_stripped:
            in_implementation = not in_implementation
            continue

        if in_implementation:
            impl_lines.append(INLINE_PATTERN.sub('', line, 1))
        else:
            header_lines.append(line)

    impl_lines.append('} // namespace httplib\n')

    # Write all at once
    with open(h_out, 'w') as fh, open(cc_out, 'w') as fc: # type: typing.TextIO, typing.TextIO
        fh.writelines(header_lines)
        fc.writelines(impl_lines)

    print("Wrote {} and {}".format(h_out, cc_out))
else:
    print("{} and {} are up to date".format(h_out, cc_out))