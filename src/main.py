#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from enum import Enum, IntFlag
from typing import Optional

import Evtx.Evtx as evtx
import xmltodict


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
    """
    Wazuh agent uses these when StandardEventLevel enum value is 0 (AUDIT). The valuse not used in Wazu are ignored.
    Reference: analysisd/decoders/winevtchannel.c
    """
    AuditFailure = 0x10000000000000
    AuditSuccess = 0x20000000000000


audit_policy_changes_map = {
    8448: "Success removed",
    8449: "Success added",
    8450: "Failure removed",
    8451: "Failure added"
}


def get_audit_policy_changes(original_eventdata_dict) -> Optional[str]:
    audit_policy_changes_id = original_eventdata_dict.get(
        "AuditPolicyChanges", None)
    if audit_policy_changes_id is None:
        return None

    filtered_changes = audit_policy_changes_id.replace('%%', '')
    audit_split = filtered_changes.split(",")
    audit_changes = [
        audit_policy_changes_map.get(int(change_id), "Unknown")
        for change_id in audit_split if change_id.isdigit()
    ]

    # Join the mapped descriptions with commas
    audit_final_field = ", ".join(audit_changes)

    return audit_final_field


# Define the mappings for categories and subcategories
category_mapping = {
    8272: {
        "name": "System",
        12288: "Security State Change",
        12289: "Security System Extension",
        12290: "System Integrity",
        12291: "IPsec Driver",
        12292: "Other System Events"
    },
    8273: {
        "name": "Logon/Logoff",
        12544: "Logon",
        12545: "Logoff",
        12546: "Account Lockout",
        12547: "IPsec Main Mode",
        12548: "Special Logon",
        12549: "IPSec Extended Mode",
        12550: "IPSec Quick Mode",
        12551: "Other Logon/Logoff Events",
        12552: "Network Policy Server",
        12553: "User/Device Claims",
        12554: "Group Membership"
    },
    8274: {
        "name": "Object Access",
        12800: "File System",
        12801: "Registry",
        12802: "Kernel Object",
        12803: "SAM",
        12804: "Other Object Access Events",
        12805: "Certification Services",
        12806: "Application Generated",
        12807: "Handle Manipulation",
        12808: "File Share",
        12809: "Filtering Platform Packet Drop",
        12810: "Filtering Platform Connection",
        12811: "Detailed File Share",
        12812: "Removable Storage",
        12813: "Central Policy Staging"
    },
    8275: {
        "name": "Privilege Use",
        13056: "Sensitive Privilege Use",
        13057: "Non Sensitive Privilege Use",
        13058: "Other Privilege Use Events"
    },
    8276: {
        "name": "Detailed Tracking",
        13312: "Process Creation",
        13313: "Process Termination",
        13314: "DPAPI Activity",
        13315: "RPC Events",
        13316: "Plug and Play Events",
        13317: "Token Right Adjusted Events"
    },
    8277: {
        "name": "Policy Change",
        13568: "Audit Policy Change",
        13569: "Authentication Policy Change",
        13570: "Authorization Policy Change",
        13571: "MPSSVC Rule-Level Policy Change",
        13572: "Filtering Platform Policy Change",
        13573: "Other Policy Change Events"
    },
    8278: {
        "name": "Account Management",
        13824: "User Account Management",
        13825: "Computer Account Management",
        13826: "Security Group Management",
        13827: "Distribution Group Management",
        13828: "Application Group Management",
        13829: "Other Account Management Events"
    },
    8279: {
        "name": "DS Access",
        14080: "Directory Service Access",
        14081: "Directory Service Changes",
        14082: "Directory Service Replication",
        14083: "Detailed Directory Service Replication"
    },
    8280: {
        "name": "Account Logon",
        14336: "Credential Validation",
        14337: "Kerberos Service Ticket Operations",
        14338: "Other Account Logon Events",
        14339: "Kerberos Authentication Service"
    }
}


# Function to retrieve category and subcategory
def get_category_and_subcategory(event_dict: dict) -> tuple[Optional[str], Optional[str]]:

    category_id = event_dict.get("CategoryID", None)
    if category_id is None:
        return None, None

    subcategory_id = event_dict.get("SubcategoryID", None)
    if subcategory_id is None:
        return None, None

    category_id = int(category_id.replace('%%', ''), base=10)
    subcategory_id = int(subcategory_id.replace('%%', ''), base=10)
    category = category_mapping.get(category_id, {}).get("name", "Unknown")
    subcategory = category_mapping.get(
        category_id, {}).get(subcategory_id, "Unknown")
    return category, subcategory


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
            logLevel = int(system_section["level"])
            if logLevel != 0:
                system_section["severityValue"] = (
                    StandardEventLevel(int(logLevel))).name
            elif logLevel <= 5:
                keywords = int(system_section["keywords"], 0)
                if (keywords & StandardEventKeywords.AuditFailure.value):
                    system_section["severityValue"] = "AUDIT_FAILURE"
                elif (keywords & StandardEventKeywords.AuditSuccess.value):
                    system_section["severityValue"] = "AUDIT_SUCCESS"
            else:
                system_section["severityValue"] = "UNKNOWN"

            # Format datetime. We lose one digit of precision here due to Python's datetime limitations.
            s = str(system_section["systemTime"])
            dt = datetime.strptime(
                s, '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
            result = dt.isoformat(
                timespec='microseconds').replace('+00:00', 'Z')
            system_section["systemTime"] = result

            # Populate the `eventdata` section dynamically
            event_data_fields: list = data_dict.get("Event", {}).get(
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

            # Event category, subcategory and Audit Policy Changes
            category, subcategory = get_category_and_subcategory(
                original_eventdata_dict)
            if category:
                original_eventdata_dict["category"] = category
            if subcategory:
                original_eventdata_dict["subcategory"] = subcategory
            audit_policy_changes = get_audit_policy_changes(
                original_eventdata_dict)
            if audit_policy_changes:
                original_eventdata_dict["auditPolicyChanges"] = audit_policy_changes

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
