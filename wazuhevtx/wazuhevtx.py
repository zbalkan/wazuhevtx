#!/usr/bin/env python3
import sys

if sys.platform != "win32":
    print("This script is intended to be run on Windows.")
    exit(1)

import argparse
import pathlib

# regardless of the relative path handling of the target, we want this to work
try:
    from wazuhevtx.events2json import EventsToJson
except ImportError:
    from events2json import EventsToJson


def main() -> None:
    """Main function for wazuhevtx tool."""

    parser = argparse.ArgumentParser(
        description="A Python tool that parses EVTX files or queries live events, and converts them into JSON formatted logs mimicking Wazuh agent behavior in version 4.x. wazuhevtx is designed as a helper for wazuh-logtest tool.")
    parser.add_argument("-e", "--evtx", type=pathlib.Path, action="store", required=False,
                        help="Path to the Windows EVTX event log file")
    parser.add_argument("-l", "--live", type=pathlib.Path, action="store", required=False,
                        help="Use this flag to parse the live event log from the local machine.")
    parser.add_argument("-o", "--output", type=pathlib.Path, required=False,
                        action="store", help="Path of output JSON file. If not defined, output will be printed to console.")
    args = parser.parse_args()

    # Open output file if specified, or default to printing to console
    if args.output:
        output_path = pathlib.Path(args.output)
        outfile = open(output_path, "w", encoding="utf-8")
    else:
        outfile = None

    channel = EventsToJson()

    if args.evtx:
        evtx_file = pathlib.Path(args.evtx)
        if not evtx_file.exists():
            print(f"File {evtx_file} does not exist.")
            return
        channel.from_file(evtx_file)

    else:
        evtx_file = None

        localfile = r"""
        <localfile>
        <location>Security</location>
        <log_format>eventchannel</log_format>
        <query>
        \<QueryList\>
            \<Query Id="0" Path="Security"\>
                \<Select Path="Security"\>*\</Select\>
            <!-- Wazuh default suppressed events, translated to structured XML filter -->
            <!-- The events below are too noisy but for some detection capabilities, they may need to be enabled. -->
            <!-- 4656(S, F): A handle to an object was requested. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4656)]]\</Suppress\>
            <!-- 4658(S): The handle to an object was closed. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4658)]]\</Suppress\>
            <!-- 4660(S): An object was deleted. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4660)]]\</Suppress\>
            <!-- 4663(S): An attempt was made to access an object. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4663)]]\</Suppress\>
            <!-- 4670(S): Permissions on an object were changed. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4670)]]\</Suppress\>
            <!-- 4690(S): An attempt was made to duplicate a handle to an object. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4690)]]\</Suppress\>
            <!-- 4703(S): A user right was adjusted. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4703)]]\</Suppress\>
            <!-- 4907(S): Auditing settings on object were changed. -->
                \<Suppress Path="Security"\>*[System[(EventID = 4907)]]\</Suppress\>
            <!-- 5145(S, F): A network share object was checked to see whether client can be granted desired access. -->
                \<Suppress Path="Security"\>*[System[(EventID = 5145)]]\</Suppress\>
            <!-- 5152(F): The Windows Filtering Platform blocked a packet. -->
                \<Suppress Path="Security"\>*[System[(EventID = 5152)]]\</Suppress\>
            <!-- 5156(S): The Windows Filtering Platform has permitted a connection. -->
                \<Suppress Path="Security"\>*[System[(EventID = 5156)]]\</Suppress\>
            <!-- 5157(F): The Windows Filtering Platform has blocked a connection. -->
                \<Suppress Path="Security"\>*[System[(EventID = 5157)]]\</Suppress\>
            <!-- 5447(S): A Windows Filtering Platform filter has been changed. -->
                \<Suppress Path="Security"\>*[System[(EventID = 5447)]]\</Suppress\>
            <!-- Not used by any Wazuh rule. We can suppress as 4660 and 4663 consists more information. -->
            <!-- 4659(S): A handle to an object was requested with intent to delete -->
                \<Suppress Path="Security"\>*[System[(EventID = 4659)]]\</Suppress\>
            <!-- Suppress common network noise for EventID 5140 -->
                \<Suppress Path="Security"\>*[System[(EventID=5140)]] and *[EventData[Data[@Name='AccessMask'] and Data='0x1']] and (*[EventData[Data[@Name='ShareName'] and Data='\\*\C$']] and *[EventData[Data[@Name='IpAddress'] and Data='127.0.0.1']])\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=5140)]] and *[EventData[Data[@Name='AccessMask'] and Data='0x1']] and *[EventData[Data[@Name='ShareName'] and Data='\\*\SYSVOL']]\</Suppress\>
            <!-- Suppress log off events for DWM and Font Driver Host -->
                \<Suppress Path="Security"\>*[System[(EventID=4634)]] and *[EventData[(Data[@Name='TargetDomainName'] and Data='Window Manager')]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4634)]] and *[EventData[(Data[@Name='TargetDomainName'] and Data='Font Driver Host')]]\</Suppress\>
            <!-- Suppress valid ANONYMOUS LOGOFF activites related to SMB or RDP -->
            <!-- Ref: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4634 -->
                \<Suppress Path="Security"\>*[System[(EventID=4634)]] and *[EventData[(Data[@Name='TargetUserName'] and Data='ANONYMOUS LOGON')]]\</Suppress\>
            <!-- Suppress known executables run by SYSTEM -->
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\svchost.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\services.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\SearchIndexer.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\winlogon.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\gpupdate.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\MusNotification.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\sdbinst.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\LogonUI.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\smss.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\powercfg.exe'))]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4688)]] and *[EventData[(Data[@Name='SubjectLogonId'] and (Data='0x3e7' or Data='0x3e4' or Data='0x3e5'))]] and *[EventData[(Data[@Name='ParentProcessName'] and (Data='C:\Windows\System32\CompatTelRunner.exe'))]]\</Suppress\>
            <!-- Suppress noisy "This event is logged when Windows Firewall did not apply the rule" -->
                \<Suppress Path="Security"\>*[System[(EventID=4957)]]\</Suppress\>
            <!-- Suppress noisy "The start type of the X service was changed from demand start to auto start" -->
                \<Suppress Path="Security"\>*[System[(EventID=7040)]] and *[EventData[(Data[@Name='param4'] and Data='TrustedInstaller')]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=7040)]] and *[EventData[(Data[@Name='param4'] and Data='BITS')]]\</Suppress\>
            <!-- Suppress noisy scheduled tasks managed by SYSTEM, Local Service and Network Service  -->
                \<Suppress Path="Security"\>*[System[(EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702)]] and (*[EventData[(Data[@Name='SubjectUserSid'] and Data='S-1-5-18')]])\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702)]] and (*[EventData[(Data[@Name='SubjectUserSid'] and Data='S-1-5-19')]])\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4698 or EventID=4699 or EventID=4700 or EventID=4701 or EventID=4702)]] and (*[EventData[(Data[@Name='SubjectUserSid'] and Data='S-1-5-20')]])\</Suppress\>
            <!-- Suppress noisy "A privileged service was called." -->
                \<Suppress Path="Security"\>*[System[(EventID=4673)]] and (*[EventData[(Data[@Name='ProcessName'] and Data='C:\Program Files\Google\Chrome\Application\chrome.exe')]])\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4673)]] and (*[EventData[(Data[@Name='ProcessName'] and Data='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')]])\</Suppress\>
                \<Suppress Path="Security"\>*[System[(EventID=4673)]] and (*[EventData[(Data[@Name='ProcessName'] and Data='C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_1.24.25200.0_x64__8wekyb3d8bbwe\WindowsPackageManagerServer.exe')]])\</Suppress\>
            <!-- Removes all service (success/failed) logons from being captured -->
            <!-- LogonType 5 and 0 are respectively used for services and system logons. See: http://blogs.msdn.com/b/ericfitz/archive/2008/02/26/you-learn-something-new-every-day-logon-type-0.aspx -->
                \<Suppress Path="Security"\>*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)]] and *[EventData[(Data[@Name='LogonType'] and Data='5') or (Data[@Name='LogonType'] and Data='0')]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)]] and *[EventData[(Data[@Name='TargetUserName'] and Data='ANONYMOUS LOGON')]]\</Suppress\>
                \<Suppress Path="Security"\>*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)]] and *[EventData[(Data[@Name='TargetUserSID'] and Data='S-1-5-18')]]\</Suppress\>
            \</Query\>
            \</QueryList\>
        </query>
        </localfile>
        """

        channel.from_live(localfile)

    for log in channel.to_json():
        if outfile:
            outfile.write(log)
        else:
            print(log)

    if outfile:
        outfile.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
