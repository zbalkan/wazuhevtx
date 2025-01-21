# wazuh-evtx

A Python tool that parses EVTX files and converts them into JSON formatted logs similar to Wazuh agent does. It is designed as a helper for `wazuh-logtest` tool.

Now, you can test your detection capabilities by replaying known attack samples such as [Windows EVTX Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

## Usage

```shell
usage: main.py [-h] [-o OUTPUT] evtx

Dump a binary EVTX file into JSON with a standardized structure.

positional arguments:
  evtx                  Path to the Windows EVTX event log file

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Path of output JSON file
```

## Caveats

### Workaround for testing

In order to be able to test with logtest, you need a workaround as we are sending JSON logs, not `event_channel` format.

* Navigate to `/var/ossec/ruleset/rules/0575-win-base_rules.xml` file.
* Update the rule 60000 this way:

```xml
<rule id="60000" level="2">
    <!-- category>ossec</category -->
    <!-- decoded_as>windows_eventchannel</decoded_as -->
    <decoded_as>json</decoded_as>
    <field name="win.system.providerName">\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
</rule>
```

### Message format

In the Event Viewer, there is a formatted message displayed in `General` tab. However, if you navigate to Details tab, you can see the raw XML does not have a field called Message. That field comes from [EvtFormatMessage function](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtformatmessage). When working with live logs, it is easy to get it. For instance, if you use `Get-WinEvent` cmdlet of PowerShell, you will get the Message field populated by `FormatDescription()` function, which eventually wraps the EvtFormatMessage function. They access the event log provider resources to get data about events, while it is not easy to do it with exproted logs. You may not have the same provider or same version of it locally.

I plan to add this capability, and fallback to current solution. But until then, simple concatenation of fields is the way. Expect differences in `message` field.
