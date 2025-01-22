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

In the Event Viewer, there is a formatted message displayed in the `General` tab. However, if you navigate to the `Details` tab, you can see that the raw XML does not have a field called `Message`. That field comes from [EvtFormatMessage function](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtformatmessage). For instance, if you use `Get-WinEvent` cmdlet of PowerShell, you will get the Message field populated by `FormatDescription()` function, which eventually wraps the EvtFormatMessage function.

However, there may be decoding or version issues that needs special handling. These edge cases are not documented, therefore, I added a fallback solution, basically exports all existing fields to come up with a message text.