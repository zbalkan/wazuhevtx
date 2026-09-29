import sys
import types


class WinErr(Exception):
    def __init__(self, winerror, strerror=""):
        super().__init__(strerror)
        self.winerror = winerror
        self.strerror = strerror


pywintypes = types.ModuleType("pywintypes")
pywintypes.error = WinErr

win32evtlog = types.ModuleType("win32evtlog")
win32evtlog.EvtRenderEventXml = 1
win32evtlog.EvtFormatMessageEvent = 1
win32evtlog.EvtQueryFilePath = 1
win32evtlog.EvtQueryForwardDirection = 0x100
win32evtlog.EvtRender = lambda raw, flags: raw


def no_meta(**kwargs):
    raise WinErr(2, "not found")


win32evtlog.EvtOpenPublisherMetadata = no_meta
win32evtlog.EvtFormatMessage = lambda *args, **kwargs: ""

sys.modules["pywintypes"] = pywintypes
sys.modules["win32evtlog"] = win32evtlog
