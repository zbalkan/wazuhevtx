#!/usr/bin/env python3
import sys

if sys.platform != "win32":
    print("This script is intended to be run on Windows.")
    exit(1)

import argparse
import pathlib

# regardless of the relative path handling of the target, we want this to work
try:
    from wazuhevtx.evtx2json import EvtxToJson
except ImportError:
    from evtx2json import EvtxToJson


def main() -> None:

    parser = argparse.ArgumentParser(
        description="A Python tool and library that parses EVTX files and converts them into JSON formatted logs mimicking Wazuh agent behavior in version 4.x. wazuhevtx is designed as a helper for wazuh-logtest tool.")
    parser.add_argument("evtx", type=pathlib.Path, action="store",
                        help="Path to the Windows EVTX event log file")
    parser.add_argument("-o", "--output", type=pathlib.Path, required=False,
                        action="store", help="Path of output JSON file. If not defined, output will be printed to console.")
    args = parser.parse_args()

    # Open output file if specified, or default to printing to console
    if args.output:
        output_path = pathlib.Path(args.output)
        outfile = open(output_path, "w", encoding="utf-8")
    else:
        outfile = None

    evtx_file = pathlib.Path(args.evtx)
    if not evtx_file.exists():
        print(f"File {evtx_file} does not exist.")
        return

    converter = EvtxToJson()
    for log in converter.to_json(evtx_file):
        if outfile:
            outfile.write(log + "\n")
        else:
            print(log)

    if outfile:
        outfile.close()


if __name__ == "__main__":
    main()
