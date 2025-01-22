# Reference: https://birolcapa.github.io/software/2021/09/24/how-to-read-evtx-file-using-python.html
import json
import pathlib
from enum import Enum, IntFlag
from typing import Optional

import win32evtlog
import xmltodict


class EvtxToJson:

    _path: Optional[str] = None

    __audit_policy_changes_map = {
        8448: "Success removed",
        8449: "Success added",
        8450: "Failure removed",
        8451: "Failure added"
    }

    __category_mapping = {
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

    def to_json(self, evtx_file: pathlib.Path) -> list[str]:

        self._path = str(evtx_file.absolute())

        windows_events: list[str] = []
        query_handle = win32evtlog.EvtQuery(str(self._path),
                                            win32evtlog.EvtQueryFilePath | win32evtlog.EvtQueryReverseDirection)

        while True:
            raw_event_collection = win32evtlog.EvtNext(query_handle, 1)
            if len(raw_event_collection) == 0:
                break
            for raw_event in raw_event_collection:
                windows_events.append(
                    self.__parse_raw_event(raw_event))
        return windows_events

    def __parse_raw_event(self, raw_event) -> str:
        record = win32evtlog.EvtRender(
            raw_event, win32evtlog.EvtRenderEventXml)
        data_dict = xmltodict.parse(record)

        # Initialize a dictionary for the standardized log structure
        standardized_log = {
            "win": {
                "system": {},
                "eventdata": {}
            }
        }

        # Populate the `system` section with normalized common fields
        event_system = standardized_log["win"]["system"]

        # Apply normalization for common fields in the `system` section
        for xml_path, target_key in self.common_fields.items():
            keys = xml_path.split(".")
            value = data_dict.get("Event", {}).get("System", {})
            for key in keys:
                value = value.get(key, {}) if isinstance(value, dict) else None
                if value:
                    if isinstance(value, str) and len(value) == 0:
                        continue

                    if key == "Correlation":  # Skip empty values in Correlation
                        if not any(value.values()):  # type: ignore
                            continue
                    else:
                        event_system[target_key] = value

        # Set the severity value after processing common fields
        logLevel = int(event_system["level"])
        if logLevel != 0:
            event_system["severityValue"] = (
                self.StandardEventLevel(int(logLevel))).name
        elif logLevel <= 5:
            keywords = int(event_system["keywords"], 0)
            if (keywords & self.StandardEventKeywords.AuditFailure.value):
                event_system["severityValue"] = "AUDIT_FAILURE"
            elif (keywords & self.StandardEventKeywords.AuditSuccess.value):
                event_system["severityValue"] = "AUDIT_SUCCESS"
            else:
                event_system["severityValue"] = "UNKNOWN"

        # Format datetime. We lose one digit of precision here due to Python's datetime limitations.
        event_system["systemTime"] = str(event_system["systemTime"])

        # Capture the original `eventdata` dictionary to format `message`
        event_data = {}
        for item in data_dict.get("Event", {}).get("EventData", {}).get("Data", []):
            if isinstance(item, dict):
                key = item.get("@Name", "Unknown")
                value = item.get("#text", "")

                if value == '-' or value == '':
                    continue

                # Cleanup hex values - remove padding zeroes
                if value is not None and str(value).startswith("0x"):
                    value = hex(int(value, 16))

                event_data[key] = value

        # Event category, subcategory and Audit Policy Changes
        category, subcategory = self.__get_category_and_subcategory(
            event_data)
        if category:
            event_data["category"] = category
        if subcategory:
            event_data["subcategory"] = subcategory
        audit_policy_changes = self.__get_audit_policy_changes(event_data)
        if audit_policy_changes:
            event_data["auditPolicyChanges"] = audit_policy_changes

        # Extract formatted message or fallback to manually crafted message
        try:
            metadata = win32evtlog.EvtOpenPublisherMetadata(
                PublisherIdentity=event_system['providerName'], Session=None, LogFilePath=self._path, Locale=0, Flags=0)
        except Exception:
            pass
        else:
            try:
                message = win32evtlog.EvtFormatMessage(
                    metadata, raw_event, win32evtlog.EvtFormatMessageEvent)
                event_system["message"] = message
            except Exception:
                # Failed to get formatted message, fallback to manually crafted message
                event_system["message"] = "\r\n".join([f"{key}: {value}" for key,
                                                       value in event_data.items()])

        # Convert EventData fields to camelCase
        # We do this after we crafted message to keep field names consistent in Message pseudo-field
        standardized_log["win"]["eventdata"] = self.__convert_keys_to_camel_case(  # type: ignore
            event_data)

        # Write or print each JSON entry as newline-delimited JSON
        return json.dumps(standardized_log) + '\n'

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

    def __get_audit_policy_changes(self, original_eventdata_dict) -> Optional[str]:
        audit_policy_changes_id = original_eventdata_dict.get(
            "AuditPolicyChanges", None)
        if audit_policy_changes_id is None:
            return None

        filtered_changes = audit_policy_changes_id.replace('%%', '')
        audit_split = filtered_changes.split(",")
        audit_changes = [
            self.__audit_policy_changes_map.get(int(change_id), "Unknown")
            for change_id in audit_split if change_id.isdigit()
        ]

        # Join the mapped descriptions with commas
        audit_final_field = ", ".join(audit_changes)

        return audit_final_field

    def __get_category_and_subcategory(self, event_dict: dict) -> tuple[Optional[str], Optional[str]]:

        category_id = event_dict.get("CategoryID", None)
        if category_id is None:
            return None, None

        subcategory_id = event_dict.get("SubcategoryID", None)
        if subcategory_id is None:
            return None, None

        category_id = int(category_id.replace('%%', ''), base=10)
        subcategory_id = int(subcategory_id.replace('%%', ''), base=10)
        category = self.__category_mapping.get(
            category_id, {}).get("name", "Unknown")
        subcategory = self.__category_mapping.get(
            category_id, {}).get(subcategory_id, "Unknown")
        return category, subcategory

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

    def __pascal_to_camelcase(self, name: str) -> str:
        return name[0].lower() + name[1:]

    def __convert_keys_to_camel_case(self, data):
        """
        Recursive function to apply camelCase conversion to all keys in a nested dictionary structure.
        """
        if isinstance(data, dict):
            return {self.__pascal_to_camelcase(k): self.__convert_keys_to_camel_case(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.__convert_keys_to_camel_case(i) for i in data]
        else:
            return data