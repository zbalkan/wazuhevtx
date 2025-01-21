#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from enum import Enum, IntFlag

import Evtx.Evtx as evtx
import xmltodict

# Function to convert keys to camelCase


def regular_to_camelcase(name: str) -> str:
    output = ''.join(x for x in name.title() if x.isalnum())
    return output[0].lower() + output[1:]


def pascal_to_camelcase(name: str) -> str:
    return name[0].lower() + name[1:]


def convert_keys_to_camel_case(data):
    """
    Recursive function to apply camelCase conversion to all keys in a nested dictionary structure.
    """
    if isinstance(data, dict):
        return {pascal_to_camelcase(k): convert_keys_to_camel_case(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_keys_to_camel_case(i) for i in data]
    else:
        return data


class StandardEventLevel(Enum):
    """
    Enum for standardizing event log levels
    Reference: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
    """
    AUDIT = 0  # How Wazuh handles this
    CRITICAL = 1
    ERROR = 2
    WARNING = 3
    INFORMATION = 4
    VERBOSE = 5


class StandardEventKeywords(IntFlag):
    """Defines the standard keywords that are attached to events by the event provider.
    Reference: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventkeywords

    Wazuh agent uses these when StandardEventLevel enum value is 0 (AUDIT). The valuse not used in Wazu are ignored.
    """
    AuditFailure = 0x10000000000000
    AuditSuccess = 0x20000000000000


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file into JSON with a standardized structure.")
    parser.add_argument("evtx", type=str, action="store",
                        help="Path to the Windows EVTX event log file")
    parser.add_argument("-o", "--output", type=str,
                        action="store", help="Path of output JSON file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:

        # Open output file if specified, or default to printing to console
        if args.output:
            output_path = args.output if args.output.endswith(
                ".json") else args.output + ".json"
            outfile = open(output_path, "w")
        else:
            outfile = None

        # Define a set of common fields for normalization
        common_fields = {
            "Provider.@Name": "providerName",
            "Provider.@Guid": "providerGuid",
            "EventID.#text": "eventID",
            "Version": "version",
            "Level": "level",
            "Task": "task",
            "Opcode": "opcode",
            "Keywords": "keywords",
            "TimeCreated.@SystemTime": "systemTime",
            "EventRecordID": "eventRecordID",
            "Execution.@ProcessID": "processID",
            "Execution.@ThreadID": "threadID",
            "Channel": "channel",
            "Computer": "computer",
            "Severity": "severityValue",
            "Correlation": "correlation",
        }

        # Process each record in the EVTX file
        for record in log.records():
            data_dict = xmltodict.parse(record.xml())

            # Initialize a dictionary for the standardized log structure
            standardized_log = {
                "win": {
                    "system": {},
                    "eventdata": {}
                }
            }

            # Populate the `system` section with normalized common fields
            system_section = standardized_log["win"]["system"]
            system_fields = data_dict.get("Event", {}).get("System", {})

            # Apply normalization for common fields in the `system` section
            for xml_path, target_key in common_fields.items():
                keys = xml_path.split(".")
                value = system_fields
                for key in keys:
                    value = value.get(key, {}) if isinstance(
                        value, dict) else None
                if value:
                    if isinstance(value, str) and len(value) == 0:
                        continue

                    if key == "Correlation":  # Skip empty values in Correlation
                        if not any(value.values()):  # type: ignore
                            continue
                    else:
                        system_section[target_key] = value

            # Set the severity value after processing common fields
            logLevel = system_section["level"]
            if logLevel != "0":
                system_section["severityValue"] = (
                    StandardEventLevel(int(logLevel))).name
            else:
                keywords = int(system_section["keywords"], 0)

                if (keywords & StandardEventKeywords.AuditFailure.value):
                    system_section["severityValue"] = "AUDIT_FAILURE"
                elif (keywords & StandardEventKeywords.AuditSuccess.value):
                    system_section["severityValue"] = "AUDIT_SUCCESS"

            # Format datetime. We lose one digit of precision here due to Python's datetime limitations.
            s = str(system_section["systemTime"])
            dt = datetime.strptime(
                s, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            result = dt.isoformat(
                timespec='microseconds').replace('+00:00', 'Z')
            system_section["systemTime"] = result

            # Populate the `eventdata` section dynamically
            event_data_fields = data_dict.get("Event", {}).get(
                "EventData", {}).get("Data", [])

            # Capture the original `eventdata` dictionary to format `message`
            original_eventdata_dict = {}
            for item in event_data_fields:
                if isinstance(item, dict):
                    key = item.get("@Name", "Unknown")
                    value = item.get("#text", "")

                    # Cleanup hex values - remove padding zeroes
                    if value is not None and str(value).startswith("0x"):
                        value = hex(int(value, 16))

                    original_eventdata_dict[key] = value

            # Create the `message` field in the original format
            # The generated message is not the same with the original message field in the event log.
            # The message field is generated by Widwos API EvtFormatMessage, not in the EVTX file.
            message_lines = [f"{key}: {value}" for key,
                             value in original_eventdata_dict.items()]
            system_section["message"] = "\r\n".join(message_lines)

            # Convert EventData fields to camelCase generically
            standardized_log["win"]["eventdata"] = convert_keys_to_camel_case(  # type: ignore
                original_eventdata_dict)

            # Write or print each JSON entry as newline-delimited JSON
            json_output = json.dumps(standardized_log)
            if outfile:
                outfile.write(json_output + "\n")
            else:
                print(json_output)

        # Close the output file if used
        if outfile:
            outfile.close()


if __name__ == "__main__":
    main()
