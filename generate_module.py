#!/usr/bin/env python3

"""This script generates httplib.cppm module file from httplib.h."""

import os
import sys
from argparse import ArgumentParser, Namespace
from typing import List

def main() -> None:
    """Main entry point for the script."""

    args_parser: ArgumentParser = ArgumentParser(description=__doc__)
    args_parser.add_argument(
        "-o", "--out", help="where to write the files (default: out)", default="out"
    )
    args: Namespace = args_parser.parse_args()

    cur_dir: str = os.path.dirname(sys.argv[0])
    if not cur_dir:
        cur_dir = '.'
    lib_name: str = "httplib"
    header_name: str = f"/{lib_name}.h"
    # get the input file
    in_file: str = f"{cur_dir}{header_name}"
    # get the output file
    cppm_out: str = f"{args.out}/{lib_name}.cppm"

    # if the modification time of the out file is after the in file,
    # don't generate (as it is already finished)
    do_generate: bool = True

    if os.path.exists(cppm_out):
        in_time: float = os.path.getmtime(in_file)
        out_time: float = os.path.getmtime(cppm_out)
        do_generate: bool = in_time > out_time

    if do_generate:
        with open(in_file) as f:
            lines: List[str] = f.readlines()

        os.makedirs(args.out, exist_ok=True)

        # Find the Headers and Declaration comment markers
        headers_start: int = -1
        declaration_start: int = -1
        for i, line in enumerate(lines):
            if ' * Headers' in line:
                headers_start = i - 1  # Include the /* line
            elif ' * Declaration' in line:
                declaration_start = i - 1  # Stop before the /* line
                break

        with open(cppm_out, 'w') as fm:
            # Write module file
            fm.write("module;\n\n")
            
            # Write global module fragment (from Headers to Declaration comment)
            # Filter out 'using' declarations to avoid conflicts
            if headers_start >= 0 and declaration_start >= 0:
                for i in range(headers_start, declaration_start):
                    line: str = lines[i]
                    if 'using' not in line:
                        fm.write(line)
            
            fm.write("\nexport module httplib;\n\n")
            fm.write("export extern \"C++\" {\n")
            fm.write(f"{' ' * 4}#include \"httplib.h\"\n")
            fm.write("}\n")

        print(f"Wrote {cppm_out}")
    else:
        print(f"{cppm_out} is up to date")


if __name__ == "__main__":
    main()
