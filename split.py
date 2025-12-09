#!/usr/bin/env python3

"""This script splits httplib.h into .h and .cc parts."""

import os
import sys
from argparse import ArgumentParser, Namespace
from typing import List


def main() -> None:
    """Main entry point for the script."""
    BORDER: str = '// ----------------------------------------------------------------------------'

    args_parser: ArgumentParser = ArgumentParser(description=__doc__)
    args_parser.add_argument(
        "-e", "--extension", help="extension of the implementation file (default: cc)",
        default="cc"
    )
    args_parser.add_argument(
        "-o", "--out", help="where to write the files (default: out)", default="out"
    )
    args: Namespace = args_parser.parse_args()

    cur_dir: str = os.path.dirname(sys.argv[0])
    if not cur_dir:
        cur_dir = '.'
    lib_name: str = 'httplib'
    header_name: str = f"/{lib_name}.h"
    source_name: str = f"/{lib_name}.{args.extension}"
    # get the input file
    in_file: str = cur_dir + header_name
    # get the output file
    h_out: str = args.out + header_name
    cc_out: str = args.out + source_name

    # if the modification time of the out file is after the in file,
    # don't split (as it is already finished)
    do_split: bool = True

    if os.path.exists(h_out):
        in_time: float = os.path.getmtime(in_file)
        out_time: float = os.path.getmtime(h_out)
        do_split: bool = in_time > out_time

    if do_split:
        with open(in_file) as f:
            lines: List[str] = f.readlines()

        os.makedirs(args.out, exist_ok=True)

        in_implementation: bool = False
        cc_out: str = args.out + source_name
        with open(h_out, 'w') as fh, open(cc_out, 'w') as fc:
            fc.write('#include "httplib.h"\n')
            fc.write('namespace httplib {\n')
            for line in lines:
                is_border_line: bool = BORDER in line
                if is_border_line:
                    in_implementation: bool = not in_implementation
                elif in_implementation:
                    fc.write(line.replace('inline ', ''))
                else:
                    fh.write(line)
            fc.write('} // namespace httplib\n')

        print(f"Wrote {h_out} and {cc_out}")
    else:
        print(f"{h_out} and {cc_out} are up to date")


if __name__ == "__main__":
    main()
