#!/usr/bin/env python3

"""This script splits httplib.h into .h and .cc parts."""

import os
import sys

BORDER = (
    "// ----------------------------------------------------------------------------"
)


def walk_dir(file_name, directory):
    for root, subdirs, files in os.walk(directory):
        if file_name in files:
            return os.path.join(root, file_name)
        for subdir in subdirs:
            return walk_dir(file_name, os.path.join(root, subdir))


def locate_file(file_name, search_dirs):
    cur_dir = os.path.dirname(sys.argv[0])
    initial_path = os.path.join(cur_dir, file_name)

    if os.path.isfile(initial_path):
        return initial_path

    for directory in search_dirs:
        result = walk_dir(file_name, os.path.join(cur_dir, directory))
        if result:
            return result

    return None


def split(lib_name, search_dirs=[], extension="cc", out="out"):
    header_name = lib_name + ".h"
    source_name = lib_name + "." + extension
    in_file = locate_file(header_name, search_dirs)
    if not in_file:
        print("File not found: {}".format(header_name))
        return

    h_out = os.path.join(out, header_name)
    cc_out = os.path.join(out, source_name)

    # if the modification time of the out file is after the in file,
    # don't split (as it is already finished)
    do_split = True

    if os.path.exists(h_out):
        in_time = os.path.getmtime(in_file)
        out_time = os.path.getmtime(h_out)
        do_split = in_time > out_time

    if do_split:
        with open(in_file) as f:
            lines = f.readlines()

        python_version = sys.version_info[0]
        if python_version < 3:
            os.makedirs(out)
        else:
            os.makedirs(out, exist_ok=True)

        in_implementation = False
        with open(h_out, "w") as fh, open(cc_out, "w") as fc:
            fc.write('#include "{}"\n'.format(header_name))
            fc.write("namespace httplib {\n")
            for line in lines:
                is_border_line = BORDER in line
                if is_border_line:
                    in_implementation = not in_implementation
                elif in_implementation:
                    fc.write(line.replace("inline ", ""))
                else:
                    fh.write(line)
            fc.write("} // namespace httplib\n")

        print("Wrote {} and {}".format(h_out, cc_out))
    else:
        print("{} and {} are up to date".format(h_out, cc_out))


def main():
    import argparse

    args_parser = argparse.ArgumentParser(description=__doc__)
    args_parser.add_argument(
        "-e",
        "--extension",
        help="extension of the implementation file (default: cc)",
        default="cc",
    )
    args_parser.add_argument(
        "-o", "--out", help="where to write the files (default: out)", default="out"
    )
    args_parser.add_argument(
        "-l",
        "--library",
        action="append",
        dest="libraries",
        help="the libraries to split (default: [httplib])",
    )
    args = args_parser.parse_args()

    default_libraries = ["httplib"]
    search_dirs = ["example"]

    for lib_name in args.libraries or default_libraries:
        split(lib_name, search_dirs, args.extension, args.out)


if __name__ == "__main__":
    main()
