# Description: This script reads an EVTX file and converts it to JSON format.
# The way to import EVTX files are based on the example of Birol Capa's blog post.
# Reference: https://birolcapa.github.io/software/2021/09/24/how-to-read-evtx-file-using-python.html
# Other behaviors are based on Wazuh agent's behavior.
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ElementTree
from enum import Enum, IntFlag
from typing import Any, Generator, Optional

import pywintypes
import win32evtlog


class EvtxToJson:

    BATCH_SIZE: int = 50

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

    def to_json(self, evtx_file: pathlib.Path) -> Generator[str, Any, None]:

        if (isinstance(evtx_file, str)):
            evtx_file = pathlib.Path(evtx_file)

        self._path = str(evtx_file.absolute())

        query_handle = win32evtlog.EvtQuery(str(self._path),
                                            win32evtlog.EvtQueryFilePath | win32evtlog.EvtQueryForwardDirection)

        while True:
            try:
                raw_event_collection = win32evtlog.EvtNext(
                    query_handle, self.BATCH_SIZE)
            except pywintypes.error as e:
                print(f"Error: {e.strerror} ({e.winerror})")
                return
            except Exception as e:
                print(f"Error: {e}")
                return

            if len(raw_event_collection) == 0:
                break
            for raw_event in raw_event_collection:
                parsed_event = self.__parse_raw_event(raw_event)
                if parsed_event is not None:
                    yield parsed_event

    def __parse_raw_event(self, raw_event) -> Optional[str]:
        record = self.__replace_lone_surrogates(win32evtlog.EvtRender(
            raw_event, win32evtlog.EvtRenderEventXml))

        # Wazuh 4.14.10: src/logcollector/read_win_event_channel.c:482-519
        # (A1, A2). The provider message is rendered before the XML whitespace
        # transformation, and Message is omitted when rendering fails.
        provider_name = self.__provider_name_from_xml(record)
        message = self.__format_message(raw_event, provider_name) if provider_name else None
        record = self.__format_event_string(record)
        record_id = self.__record_id_from_xml(record)

        if self.__agent_payload_too_large(record, message, record_id):
            return None

        event = self.__parse_event_xml(record, record_id)
        if event is None:
            return self.__collapsed_event(message)

        event_system, level, keywords = self.__parse_system(event)
        has_level_and_keywords = level is not None and keywords is not None

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:333-366
        # (Y3). severityValue follows the System fields and needs both
        # elements.
        if has_level_and_keywords:
            event_system["severityValue"] = self.__severity_value(level, keywords)

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:64-86,
        # 683-691 and src/shared/string_op.c:952 (Y4).
        if message is not None:
            event_system["message"] = self.__format_wazuh_message(message)

        standardized_win: dict = {"system": event_system}

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:697-715 (E7).
        event_data = self.__parse_event_data(event, has_level_and_keywords)
        if event_data:
            standardized_win["eventdata"] = event_data

        extra_name, extra_data = self.__parse_extra_data(event)
        if extra_name is not None:
            standardized_win[self.__pascal_to_camelcase(extra_name)] = extra_data

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:725 (S1-S3).
        return self.__serialize({"win": standardized_win})

    def __agent_payload_too_large(self, record: str, message: Optional[str], record_id: str) -> bool:
        # Wazuh 4.14.10: src/logcollector/read_win_event_channel.c:509-526,
        # src/os_crypto/shared/msgs.c:600-607 and src/client-agent/sendmsg.c:38-42
        # (T1). Oversized EventChannel messages are dropped before analysisd.
        agent_event = {}
        if message is not None:
            agent_event["Message"] = message
        agent_event["Event"] = record
        payload_size = len(self.__serialize(agent_event).encode("utf-8"))
        if payload_size <= 65393:
            return False
        print(
            f"Warning: dropped EventChannel record from {self._path} "
            f"(record ID {record_id}, JSON bytes {payload_size})",
            file=sys.stderr,
        )
        return True

    def __parse_event_xml(self, record: str, record_id: str) -> Optional[ElementTree.Element]:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:152-155
        # and src/os_xml/os_xml.c (X1-X5). DecodeWinevt passes the compact JSON
        # string representation of Event to os_xml. EvtRender uses single-quoted
        # attributes, so cJSON escaping remains parseable while XML-derived
        # values retain one cJSON escaping layer. Protect '&' only for the
        # structural parser so it does not decode entities that os_xml keeps.
        parser_record = self.__cjson_string_content(record)
        parser_record = parser_record.replace("&", "&amp;")
        try:
            event = ElementTree.fromstring(parser_record)
            if self.__xml_value_too_large(event):
                raise ValueError("os_xml value limit exceeded")
            return event
        except Exception:
            # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:155-163,
            # 683-729 (X3, X4). XML failure collapses the decoded event to the
            # system message, if the agent had rendered one.
            print(
                f"Warning: failed to parse EventChannel XML from {self._path} "
                f"(record ID {record_id})",
                file=sys.stderr,
            )
            return None

    def __parse_system(self, event: ElementTree.Element) -> tuple[dict, Optional[str], Optional[str]]:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:168-226
        # (S3, Y1, Y2). System fields are appended in XML order. Correlation,
        # securityUserID and userID keep the 4.14.10 quirks and are not emitted
        # for real EvtRender XML. Level and Keywords are returned as None only
        # when the element is absent.
        event_system: dict = {}
        level: Optional[str] = None
        keywords: Optional[str] = None

        system = self.__xml_child(event, "System")
        if system is None:
            return event_system, level, keywords

        for node in system:
            element = self.__xml_tag(node.tag)
            if element == "Provider":
                self.__add_system_attributes(node, event_system, {
                    "Name": "providerName",
                    "Guid": "providerGuid",
                    "EventSourceName": "eventSourceName",
                })
            elif element == "TimeCreated":
                attrs = list(node.attrib.items())
                if attrs and self.__xml_tag(attrs[0][0]) == "SystemTime":
                    event_system["systemTime"] = str(attrs[0][1])
            elif element == "Execution":
                self.__add_system_attributes(node, event_system, {
                    "ProcessID": "processID",
                    "ThreadID": "threadID",
                })
            elif element == "Channel":
                # Upstream adds channel unconditionally, even when empty.
                event_system["channel"] = self.__xml_content(node, empty="")
            elif element == "Level":
                level = self.__xml_content(node, empty="")
                event_system["level"] = level
            elif element == "Keywords":
                keywords = self.__xml_content(node, empty="")
                event_system["keywords"] = keywords
            elif element in ("Security", "Correlation"):
                continue
            else:
                value = self.__xml_content(node)
                if value:
                    event_system[self.__pascal_to_camelcase(element)] = value

        return event_system, level, keywords

    def __add_system_attributes(self, node: ElementTree.Element, event_system: dict,
                                field_names: dict) -> None:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:176-198 (Y1).
        # Only the listed attributes are emitted, in XML attribute order.
        for attr, value in node.attrib.items():
            field_name = field_names.get(self.__xml_tag(attr))
            if field_name is not None:
                event_system[field_name] = str(value)

    def __severity_value(self, level: str, keywords: str) -> str:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:333-366 (Y3).
        # strtol() yields 0 for a non-numeric or empty level, which takes the
        # AUDIT branch like any level 0.
        level_n = self.__parse_strtol(level, 10)
        keywords_n = self.__parse_strtoull(keywords, 16)
        severity_value = {
            1: "CRITICAL",
            2: "ERROR",
            3: "WARNING",
            4: "INFORMATION",
            5: "VERBOSE",
        }.get(level_n)
        if severity_value is None and level_n == 0:
            if keywords_n & self.StandardEventKeywords.AuditFailure.value:
                severity_value = "AUDIT_FAILURE"
            elif keywords_n & self.StandardEventKeywords.AuditSuccess.value:
                severity_value = "AUDIT_SUCCESS"
        return severity_value or "UNKNOWN"

    def __parse_event_data(self, event: ElementTree.Element, has_level_and_keywords: bool) -> dict:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:227-293
        # (E1-E4). Values already contain the P6/X2 escaping layer.
        event_data: dict = {}
        unnamed_data: list = []
        enrichment_ids: dict = {}

        event_data_section = self.__xml_child(event, "EventData")
        if event_data_section is not None:
            for node in event_data_section:
                value = self.__xml_content(node)
                if not self.__event_value_is_valid(value):
                    continue
                filtered_value = self.__trim_trailing_whitespace(value)
                element = self.__xml_tag(node.tag)
                if element != "Data":
                    event_data[self.__pascal_to_camelcase(element)] = filtered_value
                elif node.attrib:
                    self.__add_data_attributes(node, filtered_value, event_data, enrichment_ids)
                elif filtered_value:
                    unnamed_data.append(filtered_value)

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:333,
        # 370-637 (E6). Enrichment shares the Level+Keywords gate.
        category_id = enrichment_ids.get("categoryId")
        subcategory_id = enrichment_ids.get("subcategoryId")
        if has_level_and_keywords and category_id is not None and subcategory_id is not None:
            category, subcategory = self.__get_category_and_subcategory(
                category_id, subcategory_id)
            if category:
                event_data["category"] = category
            if subcategory:
                event_data["subcategory"] = subcategory

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:640-677 (E5).
        # Unlike E6, this block sits outside the Level+Keywords gate.
        audit_policy_changes_id = enrichment_ids.get("auditPolicyChanges")
        if audit_policy_changes_id is not None:
            audit_policy_changes = self.__get_audit_policy_changes(
                audit_policy_changes_id)
            if audit_policy_changes:
                event_data["auditPolicyChanges"] = audit_policy_changes

        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:273-286,
        # 698-700 and src/headers/defs.h:51 (E2).
        if unnamed_data:
            event_data["data"] = self.__truncate_utf8(", ".join(unnamed_data), 65535)

        return event_data

    def __add_data_attributes(self, node: ElementTree.Element, filtered_value: str,
                              event_data: dict, enrichment_ids: dict) -> None:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:228-270 (E1, E3,
        # E5, E6). A Name attribute ends the scan; any attribute before it uses
        # its value, not its name, as the field key.
        for attr, attr_value in node.attrib.items():
            key = self.__pascal_to_camelcase(str(attr_value))
            if self.__xml_tag(attr) != "Name":
                event_data[key] = filtered_value
                continue
            if key in ("categoryId", "subcategoryId", "auditPolicyChanges"):
                enrichment_ids[key] = filtered_value
            if key == "auditPolicyChanges":
                event_data["auditPolicyChangesId"] = filtered_value
            else:
                event_data[key] = filtered_value
            break

    def __parse_extra_data(self, event: ElementTree.Element) -> tuple[Optional[str], dict]:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:294-321,
        # 716-718 (O1). All unexpected top-level children share one object;
        # the last direct child supplies its final object name.
        extra_data: dict = {}
        extra_name: Optional[str] = None
        for top_node in event:
            if self.__xml_tag(top_node.tag) in ("System", "EventData"):
                continue
            for child_node in top_node:
                extra_name = self.__xml_tag(child_node.tag)
                for grandchild_node in child_node:
                    value = self.__xml_content(grandchild_node)
                    if not self.__event_value_is_valid(value):
                        continue
                    grandchild_element = self.__xml_tag(grandchild_node.tag)
                    extra_data[self.__pascal_to_camelcase(grandchild_element)] = (
                        self.__trim_trailing_whitespace(value)
                    )
        return extra_name, extra_data

    def __format_message(self, event_handle, provider_name: str) -> Optional[str]:
        # Wazuh 4.14.10: src/logcollector/read_win_event_channel.c get_message()
        # (A2, Y4). Publisher metadata comes from the local registry (no log
        # file path) and the message is rendered with EvtFormatMessageEvent,
        # so CR/LF and surrounding whitespace are kept verbatim.
        try:
            metadata = win32evtlog.EvtOpenPublisherMetadata(
                PublisherIdentity=provider_name, Session=None, LogFilePath=None, Locale=0, Flags=0)
            message = win32evtlog.EvtFormatMessage(
                metadata, event_handle, win32evtlog.EvtFormatMessageEvent)
        except Exception:
            return None
        if message is None:
            return None
        return self.__replace_lone_surrogates(str(message))

    def __replace_lone_surrogates(self, value: str) -> str:
        # Wazuh 4.14.10: convert_windows_string() converts UTF-16 with
        # WideCharToMultiByte(CP_UTF8), which substitutes U+FFFD for unpaired
        # surrogates instead of failing.
        return re.sub("[\ud800-\udfff]", "\ufffd", value)

    def __get_audit_policy_changes(self, audit_policy_changes_id: str) -> Optional[str]:
        audit_changes = []
        for change_id in audit_policy_changes_id.replace('%%', '').split(','):
            change = self.__audit_policy_changes_map.get(
                self.__parse_strtol(change_id, 10))
            if change:
                audit_changes.append(change)

        return ", ".join(audit_changes) or None

    def __get_category_and_subcategory(
            self, category_id: str, subcategory_id: str) -> tuple[Optional[str], Optional[str]]:
        category_id_n = self.__parse_strtol(category_id.replace('%%', ''), 10)
        subcategory_id_n = self.__parse_strtol(subcategory_id.replace('%%', ''), 10)

        category_mapping = self.__category_mapping.get(category_id_n, {})
        category = category_mapping.get("name")
        subcategory = category_mapping.get(subcategory_id_n)
        return category, subcategory

    def __format_event_string(self, value: str) -> str:
        # Wazuh 4.14.10: src/logcollector/logcollector.c:1140-1163 (A1).
        chars = list(value)
        position = 0
        while position < len(chars):
            if chars[position] in ('\n', '\r', ':'):
                if chars[position] in ('\n', '\r'):
                    chars[position] = ' '
                position += 1
                while position < len(chars) and chars[position] == '\t':
                    chars[position] = ' '
                    position += 1
                continue
            position += 1
        return ''.join(chars)

    def __format_wazuh_message(self, message: str) -> str:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:64-86,683-691;
        # src/shared/string_op.c:952 (Y4).
        serialized = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        return self.__trim_trailing_whitespace(self.__unescape_json(serialized))

    def __unescape_json(self, value: str) -> str:
        unescape_map = {
            'b': '\b',
            't': '\t',
            'n': '\n',
            'f': '\f',
            'r': '\r',
            '"': '"',
            '\\': '\\',
        }
        result = []
        position = 0
        while position < len(value):
            if value[position] != '\\' or position + 1 >= len(value):
                result.append(value[position])
                position += 1
                continue

            next_char = value[position + 1]
            if next_char in unescape_map:
                result.append(unescape_map[next_char])
            else:
                result.extend(('\\', next_char))
            position += 2
        return ''.join(result)

    def __provider_name_from_xml(self, record: str) -> Optional[str]:
        # Wazuh 4.14.10: src/logcollector/read_win_event_channel.c:482-503 (A2).
        # EvtRender uses single quotes and the agent searches "Provider Name=".
        match = re.search(r"<Provider\s+Name='([^']*)'", record)
        return match.group(1) if match else None

    def __record_id_from_xml(self, record: str) -> str:
        match = re.search(r"<EventRecordID\b[^>]*>(.*?)</EventRecordID>", record)
        return match.group(1).strip() if match else "unknown"

    def __cjson_string_content(self, value: str) -> str:
        # Wazuh 4.14.10: src/analysisd/decoders/winevtchannel.c:152 (X2/P6).
        # Exclude only the surrounding JSON quotes for the structural walk.
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))[1:-1]

    def __xml_value_too_large(self, root: ElementTree.Element) -> bool:
        # Wazuh 4.14.10: src/os_xml/os_xml_internal.h:20 and
        # src/os_xml/os_xml.c:297-303 (X3).
        for node in root.iter():
            for value in node.attrib.values():
                if len(value.encode("utf-8")) >= 20480:
                    return True
            if node.text is not None and len(node.text.encode("utf-8")) >= 20480:
                return True
        return False

    def __collapsed_event(self, message: Optional[str]) -> str:
        event_system: dict = {}
        if message is not None:
            event_system["message"] = self.__format_wazuh_message(message)
        return self.__serialize({"win": {"system": event_system}})

    def __xml_tag(self, value: str) -> str:
        return value.rsplit('}', 1)[-1]

    def __xml_child(self, node: ElementTree.Element, name: str):
        for child in node:
            if self.__xml_tag(child.tag) == name:
                return child
        return None

    def __xml_content(self, node: ElementTree.Element,
                      empty: Optional[str] = None) -> Optional[str]:
        return node.text if node.text is not None else empty

    def __event_value_is_valid(self, value: Optional[str]) -> bool:
        return value is not None and value != "" and value not in ("-", "(NULL)")

    def __trim_trailing_whitespace(self, value: str) -> str:
        # Wazuh 4.14.10: replace_win_format() walks back with
        # `while (end > result && isspace(*end))`, so the first character is
        # never removed: "  " becomes " ", not "".
        end = len(value) - 1
        while end > 0 and value[end] in " \t\n\r\v\f":
            end -= 1
        return value[:end + 1]

    def __truncate_utf8(self, value: str, size: int) -> str:
        encoded = value.encode("utf-8")
        if len(encoded) <= size:
            return value
        return encoded[:size].decode("utf-8", errors="ignore")

    def __parse_strtol(self, value: Optional[str], base: int) -> int:
        # C strtol(): leading whitespace, optional sign, longest valid prefix;
        # 0 when there is no number; clamped to the 64-bit long range.
        parsed = self.__parse_c_integer(value, base)
        return max(-(1 << 63), min(parsed, (1 << 63) - 1))

    def __parse_strtoull(self, value: Optional[str], base: int) -> int:
        # C strtoull(): a negative number wraps modulo 2**64 and overflow
        # saturates at ULLONG_MAX.
        parsed = self.__parse_c_integer(value, base)
        magnitude = min(abs(parsed), (1 << 64) - 1)
        return (-magnitude) % (1 << 64) if parsed < 0 else magnitude

    def __parse_c_integer(self, value: Optional[str], base: int) -> int:
        if value is None:
            return 0
        pattern = r"^[ \t\n\r\v\f]*([+-]?[0-9]+)" if base == 10 else r"^[ \t\n\r\v\f]*([+-]?(?:0[xX])?[0-9A-Fa-f]+)"
        match = re.match(pattern, value)
        return int(match.group(1), base) if match else 0

    def __serialize(self, value: dict) -> str:
        # cJSON_PrintUnformatted emits compact JSON and raw UTF-8 (S1, S2).
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    def __pascal_to_camelcase(self, name: str) -> str:
        return name[0].lower() + name[1:] if name else name

    class StandardEventLevel(Enum):
        """
        Enum for standardizing event log levels
        Reference: https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.standardeventlevel
        """
        AUDIT = 0
        CRITICAL = 1
        ERROR = 2
        WARNING = 3
        INFORMATION = 4
        VERBOSE = 5
        UNKNOWN = 16

    class StandardEventKeywords(IntFlag):
        """
        Wazuh 4.14.10 audit keyword bits.
        Reference: src/analysisd/decoders/winevtchannel.c:333-366
        """
        AuditFailure = 0x10000000000000
        AuditSuccess = 0x20000000000000
