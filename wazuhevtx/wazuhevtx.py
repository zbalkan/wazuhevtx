#!/usr/bin/env python3
import sys

if sys.platform != "win32":
    print("This script is intended to be run on Windows.")
    exit(1)

import argparse
import pathlib

from evtx2json import EvtxToJson


def main() -> None:

    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file into JSON with a standardized structure Wazuh agent uses.")
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
    json_logs: list[str] = converter.to_json(evtx_file)

    if outfile:
        for log in json_logs:
            outfile.write(log)
        outfile.close()
    else:
        print(json_logs)


if __name__ == "__main__":
    main()
