#!/usr/bin/env python3
from evtparser import EventLogParser


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file into JSON with a standardized structure.")
    parser.add_argument("evtx", type=str, action="store",
                        help="Path to the Windows EVTX event log file")
    parser.add_argument("-o", "--output", type=str,
                        action="store", help="Path of output JSON file")
    args = parser.parse_args()

    # Open output file if specified, or default to printing to console
    if args.output:
        output_path = args.output if args.output.endswith(
            ".json") else args.output + ".json"
        outfile = open(output_path, "w", encoding="utf-8")
    else:
        outfile = None

    evtParser = EventLogParser(args.evtx)
    json_logs = evtParser.get_all_events()

    if outfile:
        for log in json_logs:
            outfile.write(log)
        outfile.close()
    else:
        print(json_logs)


if __name__ == "__main__":
    main()
