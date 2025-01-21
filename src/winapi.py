import ctypes
from ctypes import wintypes

# Load the wevtapi DLL
wevtapi = ctypes.WinDLL("wevtapi.dll")

# Define constants and types
EvtFormatMessageEvent = 1  # Specifies that we want an event message format
EvtFormatMessageId = 2     # Use for specific event ID-based messages
EvtOpenPublisherMetadata = wevtapi.EvtOpenPublisherMetadata
EvtClose = wevtapi.EvtClose
EvtFormatMessage = wevtapi.EvtFormatMessage
ERROR_INSUFFICIENT_BUFFER = 122

# Define prototypes for the WinAPI functions
EvtClose.argtypes = [wintypes.HANDLE]
EvtClose.restype = wintypes.BOOL

EvtFormatMessage.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(wintypes.WORD), wintypes.DWORD, wintypes.DWORD,
    ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)
]
EvtFormatMessage.restype = wintypes.BOOL

# Function to get the event message description from a provider


def get_event_message(provider_name, event_id):
    # Open provider metadata handle
    publisher_handle = EvtOpenPublisherMetadata(
        None, provider_name, None, 0, 0)
    if not publisher_handle:
        raise ctypes.WinError()

    try:
        # First, call with a NULL buffer to get the buffer size needed
        buffer_used = wintypes.DWORD(0)
        wevtapi.EvtFormatMessage(publisher_handle, None, event_id, 0,
                                 None, EvtFormatMessageId, 0, None, ctypes.byref(buffer_used))

        if ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError()

        # Allocate the buffer for the message
        message_buffer = ctypes.create_unicode_buffer(buffer_used.value)

        # Retrieve the formatted message
        success = wevtapi.EvtFormatMessage(
            publisher_handle, None, event_id, 0, None,
            EvtFormatMessageId, buffer_used.value, message_buffer, ctypes.byref(
                buffer_used)
        )

        if not success:
            raise ctypes.WinError()

        return message_buffer.value
    finally:
        EvtClose(publisher_handle)


# Example usage
provider_name = "Microsoft-Windows-Sysmon"  # Sysmon provider name
event_id = 1  # Event ID for "Process Create"

# Get the event message from Windows API
try:
    event_message = get_event_message(provider_name, event_id)
    print("Event Message:", event_message)
except Exception as e:
    print("Error retrieving event message:", e)
